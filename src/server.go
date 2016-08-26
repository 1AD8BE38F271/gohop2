/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: FTwOoO <booobooob@gmail.com>
 */

package hop

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"github.com/FTwOoO/water"
	"github.com/FTwOoO/water/waterutil"
	"github.com/FTwOoO/go-logger"
	"github.com/FTwOoO/go-enc"
)

const (
	IFACE_BUFSIZE = 2000
	BUF_SIZE = 2048
)

var log logger.Logger

type CandyVPNServer struct {
	// config
	cfg       CandyVPNServerConfig

	peers     *VPNPeers

	// interface
	iface     *water.Interface

	// channel to put in packets read from udpsocket
	fromNet   chan *Packet

	// channel to put packets to send through udpsocket
	toNet     chan *Packet

	// channel to put frames read from tun/tap device
	fromIface chan []byte

	// channel to put frames to send to tun/tap device
	toIface   chan *HopPacket

	pktHandle map[byte](func(*HopPacket))

	_lock     sync.RWMutex
}

func NewServer(cfg CandyVPNServerConfig) (err error) {

	log, err := logger.NewLogger(cfg.LogFile, cfg.LogLevel)
	if err != nil {
		return
	}

	cipher, err = enc.NewSalsa20BlockCrypt([]byte(cfg.Key))
	if err != nil {
		return err
	}

	hopServer := new(CandyVPNServer)
	hopServer.fromNet = make(chan *Packet, BUF_SIZE)
	hopServer.fromIface = make(chan []byte, BUF_SIZE)
	hopServer.toIface = make(chan *HopPacket, BUF_SIZE)
	hopServer.peers = make(map[uint64]*VPNPeer)
	hopServer.cfg = cfg
	hopServer.toNet = make(chan *Packet, BUF_SIZE)

	iface, err := water.NewTUN("tun1")
	if err != nil {
		return err
	}

	hopServer.iface = iface
	ip, subnet, err := net.ParseCIDR(cfg.Subnet)
	err = iface.SetupNetwork(ip, *subnet, cfg.MTU)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	err = iface.SetupNATForServer()
	if err != nil {
		log.Error(err.Error())
		return err
	}

	hopServer.peers = NewVPNPeers(subnet, hopServer.cfg.PeerTimeout)


	//读取Tun并转发:
	//[Server Tun] —> [fromIface buf] —> [toNet buf]—>udp—> [Client]

	//接收客户端节点的Data类型协议包并转发:
	//[Client] —>udp—> [fromNet buf] —> [toIface buf] —> [Server Tun]

	//接收客户端节控制类型协议包并回复:
	//[Client] —>udp—> [fromNet buf] —>udp—> [Client]


	for idx, port := 0, cfg.PortStart; port <= cfg.PortEnd; port++ {
		go hopServer.listen(PROTO_KCP, fmt.Sprintf("%s:%d", cfg.ListenAddr, port))
		idx++
	}

	go hopServer.handleInterface()
	go hopServer.forwardFrames()

	go hopServer.peerTimeoutWatcher()
	hopServer.cleanUp()
}

func (srv *CandyVPNServer) handleInterface() {
	log.Debug("Recieving iface frames")

	go func() {
		for {
			hp := <-srv.toIface
			log.Debug("New Net packet to device")
			_, err := srv.iface.Write(hp.Payload)
			if err != nil {
				return
			}
		}
	}()

	buf := make([]byte, IFACE_BUFSIZE)
	for {
		n, err := srv.iface.Read(buf)
		if err != nil {
			log.Error(err.Error())
			return
		}
		hpbuf := make([]byte, n)
		copy(hpbuf, buf)
		log.Debug("New Net packet from device")
		srv.fromIface <- hpbuf
	}
}

func (srv *CandyVPNServer) listen(protocol Protocol, addr string) {
	l, err := Listen(protocol, addr)
	if err != nil {
		log.Errorf("Failed to listen on %s: %s", addr, err.Error())
		return
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Errorf("Server %d close because of %v", addr, err)
			l.Close()
			return
		}

		go func(conn *net.Conn) {
			for {
				var plen int
				buf := make([]byte, IFACE_BUFSIZE)
				plen, err = conn.Read(buf)
				if err != nil {
					log.Error(err.Error())
					return
				}

				packet := Packet{data:buf[:plen], conn:conn}
				srv.fromNet <- packet
			}

		}(conn)
	}
}

func (srv *CandyVPNServer) forwardFrames() {

	srv.pktHandle = map[byte](func(*HopPacket)){
		HOP_FLG_PING:               srv.handleKnock,
		HOP_FLG_PING | HOP_FLG_ACK: srv.handleHeartbeatAck,
		HOP_FLG_HSH:               srv.handleHandshake,
		HOP_FLG_HSH | HOP_FLG_ACK: srv.handleHandshakeAck,
		HOP_FLG_DAT:               srv.handleDataPacket,
		HOP_FLG_DAT | HOP_FLG_MFR: srv.handleDataPacket,
		HOP_FLG_FIN:               srv.handleFinish,
	}

	go func() {
		for {
			select {
			case packet := <-srv.toNet:
				packet.Send()
			}
		}
	}()

	for {
		select {
		case pack := <-srv.fromIface:
			dest := waterutil.IPv4Destination(pack).To4()
			mkey, _ := binary.Uvarint(dest)

			log.Debugf("ip dest: %v", dest)
			if hpeer, found := srv.peers.peersByIP[mkey]; found {
				srv.toClient(hpeer, HOP_FLG_DAT, pack, true)
			} else {
				log.Warningf("client peer with key %d not found", mkey)
			}

		case packet := <-srv.fromNet:
			hPack, err := unpackHopPacket(packet.data)
			if err == nil {
				if handle_func, ok := srv.pktHandle[hPack.Flag]; ok {
					handle_func(packet, hPack)
				} else {
					log.Errorf("Unkown flag: %x", hPack.Flag)
				}
			} else {
				log.Error(err.Error())
			}
		}
	}
}

func (srv *CandyVPNServer) toClient(peer *VPNPeer, flag byte, payload []byte, noise bool) {
	hp := new(HopPacket)
	hp.Seq = peer.Seq()
	hp.Flag = flag
	hp.Payload = payload

	log.Debugf("peer: %v", peer)
	upacket := &Packet{data:hp.Pack(), conn:peer.RandomConn()}
	srv.toNet <- upacket

}

func (srv *CandyVPNServer) handleKnock(hp *HopPacket) {
	sid := hp.Sid

	hpeer, ok := srv.peers.PeersByID[sid]
	if !ok {
		srv.peers.NewPeer(sid, srv)
	} else {
		if hpeer.state == HOP_STAT_WORKING {
			srv.toClient(hpeer, HOP_FLG_PING | HOP_FLG_ACK, []byte{0}, true)
		}
	}

	hpeer.lastSeenTime = time.Now()
}

func (srv *CandyVPNServer) handleHeartbeatAck(hp *HopPacket) {
	sid := hp.Sid

	hpeer, ok := srv.peers.PeersByID[sid]
	if !ok {
		return
	}

	hpeer.lastSeenTime = time.Now()
}

func (srv *CandyVPNServer) handleHandshake(hp *HopPacket) {
	sid := hp.Sid

	var peer *VPNPeer

	peer, ok := srv.peers.PeersByID[sid]
	if !ok {
		_, err := srv.peers.NewPeer(sid, srv)
		if err != nil {
			log.Errorf("Cant alloc IP from pool %v", err)
		}

		peer, _ = srv.peers.PeersByID[sid]

	}
	buf := bytes.NewBuffer(make([]byte, 0, 8))
	buf.WriteByte(HOP_PROTO_VERSION)
	buf.Write([]byte(peer.ip))
	buf.WriteByte(byte(srv.peers.ippool.subnet.Mask.Size()))

	log.Debugf("assign address %s", peer.ip)
	atomic.StoreInt32(&peer.state, HOP_STAT_HANDSHAKE)

	srv.toClient(peer, HOP_FLG_HSH | HOP_FLG_ACK, buf.Bytes(), true)
	go func() {
		select {
		case <-peer.hsDone:
			peer.state = HOP_STAT_WORKING
			return
		case <-time.After(2 * time.Second):
			srv.toClient(peer, HOP_FLG_HSH | HOP_FLG_FIN, []byte{}, true)
			srv.peers.DeletePeer(sid)
		}
	}()

}

func (srv *CandyVPNServer) handleHandshakeAck(hp *HopPacket) {
	sid := hp.Sid
	hpeer, ok := srv.peers.PeersByID[sid]
	if !ok {
		return
	}

	log.Debug("Client Handshake Done")
	log.Infof("Client %d Connected", sid)

	if ok = atomic.CompareAndSwapInt32(&hpeer.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING); ok {
		hpeer.hsDone <- struct{}{}
	} else {
		log.Warningf("Invalid peer state: %v", hpeer.ip)
		srv.KictoutPeer(sid)
	}
}

func (srv *CandyVPNServer) handleDataPacket(hp *HopPacket) {
	sid := hp.Sid

	if hpeer, ok := srv.peers.PeersByID[sid]; ok && hpeer.state == HOP_STAT_WORKING {
		hpeer.recvBuffer.Push(hp)
		hpeer.lastSeenTime = time.Now()
	}
}

func (srv *CandyVPNServer) handleFinish(hp *HopPacket) {
	log.Infof("releasing client sid: %d", hp.Sid)
	srv.FinishPeer(hp.Sid)
}

func (srv *CandyVPNServer) KictoutPeer(sid uint32) {
	hpeer, ok := srv.peers.PeersByID[sid]
	if !ok {
		return
	}

	srv.peers.DeletePeer(sid)
	srv.toClient(hpeer, HOP_FLG_FIN, []byte{}, false)
}

func (srv *CandyVPNServer) FinishPeer(sid uint32) {
	hpeer, ok := srv.peers.PeersByID[sid]
	if !ok {
		return
	}

	srv.peers.DeletePeer(sid)
	srv.toClient(hpeer, HOP_FLG_FIN | HOP_FLG_ACK, []byte{}, false)
}

func (srv *CandyVPNServer) cleanUp() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)
	<-c

	for _, hpeer := range srv.peers.PeersByID {
		srv.toClient(hpeer, HOP_FLG_FIN | HOP_FLG_ACK, []byte{}, false)
		srv.toClient(hpeer, HOP_FLG_FIN, []byte{}, false)
	}
	os.Exit(0)
}

func (srv *CandyVPNServer) peerTimeoutWatcher() {
	timeout := time.Second * time.Duration(srv.cfg.PeerTimeout)

	for {
		select {
		case <-time.After(timeout):
			for sid, hpeer := range srv.peers.PeersByID {
				log.Debugf("IP: %v, sid: %v", hpeer.ip, sid)
				srv.toClient(hpeer, HOP_FLG_PING, []byte{}, false)
			}
		case peer := <-srv.peers.PeerTimeout:
			srv.toClient(peer, HOP_FLG_FIN, []byte{}, false)
		}
	}
}

