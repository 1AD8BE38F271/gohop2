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
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"github.com/FTwOoO/water"
	"github.com/FTwOoO/water/waterutil"
	"github.com/apsdehal/go-logger"
	"github.com/FTwOoO/go-enc"
)

const (
	IFACE_BUFSIZE = 2000
)


// a udpPacket
type udpPacket struct {
	// client's addr
	addr    *net.UDPAddr
	// data
	data    []byte
	// channel
	channel int
}

type CandyVPNServer struct {
	// config
	cfg          CandyVPNServerConfig
	// interface
	iface        *water.Interface
	// subnet
	ipnet        *net.IPNet
	// IP Pool
	ippool       *IPPool
	// client peers, key is the mac address, value is a HopPeer record
	peers        map[uint64]*VPNPeer

	// channel to put in packets read from udpsocket
	fromNet      chan *udpPacket
	// channel to put packets to send through udpsocket
	toNet        []chan *udpPacket
	// channel to put frames read from tun/tap device
	fromIface    chan []byte
	// channel to put frames to send to tun/tap device
	toIface      chan *HopPacket

	pktHandle    map[byte](func(*udpPacket, *HopPacket))

	_lock        sync.RWMutex
	_chanBufSize int
}

func NewServer(cfg CandyVPNServerConfig) error {
	var err error
	cipher, err = enc.NewSalsa20BlockCrypt([]byte(cfg.Key))
	if err != nil {
		return err
	}

	hopServer := new(CandyVPNServer)
	hopServer._chanBufSize = 2048
	hopServer.fromNet = make(chan *udpPacket, hopServer._chanBufSize)
	hopServer.fromIface = make(chan []byte, hopServer._chanBufSize)
	hopServer.toIface = make(chan *HopPacket, hopServer._chanBufSize)
	hopServer.peers = make(map[uint64]*VPNPeer)
	hopServer.cfg = cfg
	hopServer.toNet = make([]chan *udpPacket, (cfg.HopEnd - cfg.HopStart + 1))
	hopServer.ippool = new(IPPool)

	iface, err := water.NewTUN("tun1")
	if err != nil {
		return err
	}

	hopServer.iface = iface
	ip, subnet, err := net.ParseCIDR(cfg.Subnet)
	err = iface.SetupNetwork(ip, *subnet, cfg.MTU)
	if err != nil {
		logger.Error(err)
		return err
	}

	err = iface.SetupNATForServer()
	if err != nil {
		logger.Error(err)
		return err
	}

	hopServer.ipnet = &net.IPNet{ip, subnet.Mask}
	hopServer.ippool.subnet = subnet


	//读取Tun并转发:
	//[Server Tun] —> [fromIface buf] —> [toNet buf]—>udp—> [Client]

	//接收客户端节点的Data类型协议包并转发:
	//[Client] —>udp—> [fromNet buf] —> [toIface buf] —> [Server Tun]

	//接收客户端节控制类型协议包并回复:
	//[Client] —>udp—> [fromNet buf] —>udp—> [Client]

	go hopServer.forwardFrames()
	go hopServer.cleanUp()

	// serve for multiple ports
	for idx, port := 0, cfg.HopStart; port <= cfg.HopEnd; port++ {
		go hopServer.listenAndServe(cfg.ListenAddr, fmt.Sprintf("%d", port), idx)
		idx++
	}

	go hopServer.peerTimeoutWatcher()
	logger.Debug("Recieving iface frames")

	if cfg.Up != "" {
		args := strings.Split(cfg.Up, " ")
		var cmd *exec.Cmd
		if len(args) == 1 {
			cmd = exec.Command(args[0])
		} else {
			cmd = exec.Command(args[0], args[1:]...)
		}
		logger.Info(cfg.Up)
		cmd.Run()
	}

	// TODO: handle interface，下面的两段循环应该放到一个goroutine里，
	// 主程序等待它们，专门处理Tun,从toIface拿数据写入和读出到fromIface

	go func() {
		for {
			hp := <-hopServer.toIface
			logger.Debug("New Net packet to device")
			_, err := iface.Write(hp.Payload)
			if err != nil {
				return
			}
		}
	}()

	buf := make([]byte, IFACE_BUFSIZE)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			return err
		}
		hpbuf := make([]byte, n)
		copy(hpbuf, buf)
		logger.Debug("New Net packet from device")
		hopServer.fromIface <- hpbuf
	}

}

func (srv *CandyVPNServer) listenAndServe(addr string, port string, idx int) {
	port = addr + ":" + port
	udpAddr, err := net.ResolveUDPAddr("udp", port)
	if err != nil {
		logger.Errorf("Invalid port: %s", port)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.Errorf("Failed to listen udp port %s: %s", port, err.Error())
		return
	}

	toNet := make(chan *udpPacket, srv._chanBufSize)

	go func() {
		//TODO: 这里加个锁不需要这么麻烦吧？？
		defer srv._lock.Unlock()
		srv._lock.Lock()
		srv.toNet[idx] = toNet
		logger.Info("Listening on port %s", port)
	}()

	go func() {
		for {
			packet := <-toNet
			logger.Debug("sent packet to client addr: %v", packet.addr)
			udpConn.WriteTo(packet.data, packet.addr)
		}
	}()

	for {
		var plen int
		packet := new(udpPacket)
		packet.channel = idx
		buf := make([]byte, IFACE_BUFSIZE)
		plen, packet.addr, err = udpConn.ReadFromUDP(buf)
		logger.Debug("New UDP Packet from: %v", packet.addr)

		packet.data = buf[:plen]
		if err != nil {
			logger.Error(err.Error())
			return
		}

		srv.fromNet <- packet
	}

}

func (srv *CandyVPNServer) forwardFrames() {

	srv.pktHandle = map[byte](func(*udpPacket, *HopPacket)){
		HOP_FLG_PSH:               srv.handleKnock,
		HOP_FLG_PSH | HOP_FLG_ACK: srv.handleHeartbeatAck,
		HOP_FLG_HSH:               srv.handleHandshake,
		HOP_FLG_HSH | HOP_FLG_ACK: srv.handleHandshakeAck,
		HOP_FLG_DAT:               srv.handleDataPacket,
		HOP_FLG_DAT | HOP_FLG_MFR: srv.handleDataPacket,
		HOP_FLG_FIN:               srv.handleFinish,
	}

	for {
		select {
		case pack := <-srv.fromIface:
			dest := waterutil.IPv4Destination(pack).To4()
			mkey, _ := binary.Uvarint(dest)

			logger.Debug("ip dest: %v", dest)
			if hpeer, found := srv.peers[mkey]; found {
				srv.toClient(hpeer, HOP_FLG_DAT, pack, true)
			} else {
				logger.Warningf("client peer with key %d not found", mkey)
			}

		case packet := <-srv.fromNet:
			srv.handlePacket(packet)
		}

	}
}

func (srv *CandyVPNServer) handlePacket(packet *udpPacket) {
	defer func() {
		if err := recover(); err != nil {
			logger.Errorf("handleFunction failed: %v, packet addr:%v", err, packet.addr)
		}
	}()

	hPack, err := unpackHopPacket(packet.data)
	if err == nil {
		logger.Debugf("New UDP Packet [flag:%v] from : %v", hPack.Flag, packet.addr)
		if handle_func, ok := srv.pktHandle[hPack.Flag]; ok {
			handle_func(packet, hPack)
		} else {
			logger.Errorf("Unkown flag: %x", hPack.Flag)
		}
	} else {
		logger.Error(err.Error())
	}
}

func (srv *CandyVPNServer) toClient(peer *VPNPeer, flag byte, payload []byte, noise bool) {
	// TODO:noise arg is deprecated, since all packet has noice
	hp := new(HopPacket)
	hp.Seq = peer.Seq()
	hp.Flag = flag
	hp.Payload = payload

	if addr, idx, ok := peer.addr(); ok {
		logger.Debugf("peer: %v", addr)
		upacket := &udpPacket{addr, hp.Pack(), idx}
		srv.toNet[idx] <- upacket
	} else {
		logger.Debug("peer not found")
	}
}

func (srv *CandyVPNServer) handleKnock(u *udpPacket, hp *HopPacket) {
	sid := uint64(binary.BigEndian.Uint32(hp.Payload[:4]))
	logger.Debugf("port knock from client %v, sid: %d", u.addr, sid)
	sid = (sid << 32) & uint64(0xFFFFFFFF00000000)

	hpeer, ok := srv.peers[sid]
	if !ok {
		hpeer = newHopPeer(sid, srv, u.addr, u.channel)
		srv.peers[sid] = hpeer
	} else {
		hpeer.insertAddr(u.addr, u.channel)
		if hpeer.state == HOP_STAT_WORKING {
			srv.toClient(hpeer, HOP_FLG_PSH | HOP_FLG_ACK, []byte{0}, true)
		}
	}

	hpeer.lastSeenTime = time.Now()
}

func (srv *CandyVPNServer) handleHeartbeatAck(u *udpPacket, hp *HopPacket) {
	sid := uint64(binary.BigEndian.Uint32(hp.Payload[:4]))
	sid = (sid << 32) & uint64(0xFFFFFFFF00000000)

	hpeer, ok := srv.peers[sid]
	if !ok {
		return
	}

	hpeer.lastSeenTime = time.Now()
}

func (srv *CandyVPNServer) handleHandshake(u *udpPacket, hp *HopPacket) {
	sid := uint64(binary.BigEndian.Uint32(hp.Payload[:4]))
	sid = (sid << 32) & uint64(0xFFFFFFFF00000000)
	logger.Debugf("handshake from client %v, sid: %d", u.addr, sid)

	hpeer, ok := srv.peers[sid]
	if !ok {
		hpeer = newHopPeer(sid, srv, u.addr, u.channel)
		srv.peers[sid] = hpeer
	} else {
		hpeer.insertAddr(u.addr, u.channel)
	}

	cltIP, err := srv.ippool.Next()
	if err != nil {
		msg := fmt.Sprintf("%s", err.Error())
		srv.toClient(hpeer, HOP_FLG_HSH | HOP_FLG_FIN, []byte(msg), true)
		delete(srv.peers, sid)
	} else {
		hpeer.ip = cltIP.IP.To4()
		mask, _ := cltIP.Mask.Size()
		buf := bytes.NewBuffer(make([]byte, 0, 8))
		buf.WriteByte(HOP_PROTO_VERSION)
		buf.Write([]byte(hpeer.ip))
		buf.WriteByte(byte(mask))
		key, _ := binary.Uvarint(hpeer.ip)

		logger.Debugf("assign address %s, route key %d", cltIP, key)
		srv.peers[key] = hpeer
		atomic.StoreInt32(&hpeer.state, HOP_STAT_HANDSHAKE)
		srv.toClient(hpeer, HOP_FLG_HSH | HOP_FLG_ACK, buf.Bytes(), true)
		hpeer.hsDone = make(chan struct{})
		go func() {
			for i := 0; i < 5; i++ {
				select {
				case <-hpeer.hsDone:
					hpeer.state = HOP_STAT_WORKING //TODO:这行代码多余了
					return
				case <-time.After(2 * time.Second):
					logger.Debug("Client Handshake Timeout")
					srv.toClient(hpeer, HOP_FLG_HSH | HOP_FLG_ACK, buf.Bytes(), true)
				}
			}
			// timeout,  kick
			srv.toClient(hpeer, HOP_FLG_HSH | HOP_FLG_FIN, []byte{}, true)
			srv.toClient(hpeer, HOP_FLG_HSH | HOP_FLG_FIN, []byte{}, true)
			srv.toClient(hpeer, HOP_FLG_HSH | HOP_FLG_FIN, []byte{}, true)

			srv.ippool.Release(hpeer.ip)
			delete(srv.peers, sid)
			delete(srv.peers, key)

		}()
	}

}

func (srv *CandyVPNServer) handleHandshakeAck(u *udpPacket, hp *HopPacket) {
	sid := uint64(binary.BigEndian.Uint32(hp.Payload[:4]))
	sid = (sid << 32) & uint64(0xFFFFFFFF00000000)
	hpeer, ok := srv.peers[sid]
	if !ok {
		return
	}
	logger.Debug("Client Handshake Done")
	logger.Infof("Client %d Connected", sid)
	if ok = atomic.CompareAndSwapInt32(&hpeer.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING); ok {
		hpeer.hsDone <- struct{}{}
	} else {
		logger.Warningf("Invalid peer state: %v", hpeer.ip)
		srv.kickOutPeer(sid)
	}
}

func (srv *CandyVPNServer) handleDataPacket(u *udpPacket, hp *HopPacket) {
	sid := uint64(hp.Sid)
	sid = (sid << 32) & uint64(0xFFFFFFFF00000000)

	if hpeer, ok := srv.peers[sid]; ok && hpeer.state == HOP_STAT_WORKING {
		hpeer.recvBuffer.Push(hp)
		hpeer.lastSeenTime = time.Now()
	}
}

func (srv *CandyVPNServer) handleFinish(u *udpPacket, hp *HopPacket) {
	sid := uint64(binary.BigEndian.Uint32(hp.Payload[:4]))
	sid = (sid << 32) & uint64(0xFFFFFFFF00000000)
	logger.Infof("releasing client %v, sid: %d", u.addr, sid)

	srv.deletePeer(sid)
}

func (srv *CandyVPNServer) kickOutPeer(sid uint64) {
	hpeer, ok := srv.peers[sid]
	if !ok {
		return
	}
	srv.deletePeer(sid)
	srv.toClient(hpeer, HOP_FLG_FIN, []byte{}, false)
	srv.toClient(hpeer, HOP_FLG_FIN, []byte{}, false)
	srv.toClient(hpeer, HOP_FLG_FIN, []byte{}, false)
}

func (srv *CandyVPNServer) deletePeer(sid uint64) {
	hpeer, ok := srv.peers[sid]
	if !ok {
		return
	}

	key, _ := binary.Uvarint(hpeer.ip)
	srv.ippool.Release(hpeer.ip)

	delete(srv.peers, sid)
	delete(srv.peers, key)

	srv.toClient(hpeer, HOP_FLG_FIN | HOP_FLG_ACK, []byte{}, false)
	srv.toClient(hpeer, HOP_FLG_FIN | HOP_FLG_ACK, []byte{}, false)
}

func (srv *CandyVPNServer) cleanUp() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)
	<-c

	if srv.cfg.Down != "" {
		args := strings.Split(srv.cfg.Down, " ")
		var cmd *exec.Cmd
		if len(args) == 1 {
			cmd = exec.Command(args[0])
		} else {
			cmd = exec.Command(args[0], args[1:]...)
		}
		logger.Info(srv.cfg.Down)
		cmd.Run()
	}

	for _, hpeer := range srv.peers {
		srv.toClient(hpeer, HOP_FLG_FIN | HOP_FLG_ACK, []byte{}, false)
		srv.toClient(hpeer, HOP_FLG_FIN | HOP_FLG_ACK, []byte{}, false)
		srv.toClient(hpeer, HOP_FLG_FIN, []byte{}, false)
		srv.toClient(hpeer, HOP_FLG_FIN, []byte{}, false)
	}
	os.Exit(0)
}

func (srv *CandyVPNServer) peerTimeoutWatcher() {
	timeout := time.Second * time.Duration(srv.cfg.PeerTimeout)
	interval := time.Second * time.Duration(srv.cfg.PeerTimeout / 2)

	for {
		if srv.cfg.PeerTimeout <= 0 {
			return
		}
		time.Sleep(interval)
		for sid, hpeer := range srv.peers {
			// Heartbeat
			if sid < 0x01 << 32 {
				continue
			}
			logger.Debugf("IP: %v, sid: %v", hpeer.ip, sid)
			srv.toClient(hpeer, HOP_FLG_PSH, []byte{}, false)
		}
		// count := 0
		time.Sleep(interval)
		for sid, hpeer := range srv.peers {
			if sid < 0x01 << 32 {
				continue
			}
			logger.Debugf("watch: %v", hpeer.lastSeenTime)
			conntime := time.Since(hpeer.lastSeenTime)
			if conntime > timeout {
				logger.Infof("peer %v timeout", hpeer.ip)
				go srv.kickOutPeer(sid)
			}
		}
	}
}
