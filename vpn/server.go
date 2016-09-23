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

package vpn

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
	"github.com/FTwOoO/vpncore/conn"
	"github.com/FTwOoO/vpncore/tcpip"
	"github.com/FTwOoO/vpncore/tuntap"
	"github.com/FTwOoO/go-logger"
)

const (
	IFACE_BUFSIZE = 2000
	BUF_SIZE = 2048
)


type CandyVPNServer struct {
	cfg        *VPNConfig
	peers      *VPNPeers
	iface      *tuntap.Interface

	netStreams PacketStreams
	fromIface  chan []byte
	toIface    chan []byte

	pktHandle  map[Protocol](func(*VPNPeer, *HopPacket))
}

func NewServer(cfg *VPNConfig) (err error) {

	log, err := logger.NewLogger(cfg.LogFile, cfg.LogLevel)
	if err != nil {
		return
	}

	//cipher, err = enc.NewSalsa20BlockCrypt([]byte(cfg.Key))
	//if err != nil {
	//	return err
	//}

	hopServer := new(CandyVPNServer)
	hopServer.netStreams = NewPacketStreams()
	hopServer.fromIface = make(chan []byte, BUF_SIZE)
	hopServer.toIface = make(chan []byte, BUF_SIZE * 4)
	hopServer.peers = new(VPNPeers)
	hopServer.cfg = cfg

	iface, err := tuntap.NewTUN("tun1")
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

	err = iface.ServerSetupNatRules()
	if err != nil {
		log.Error(err.Error())
		return err
	}

	hopServer.peers = NewVPNPeers(subnet, time.Duration(hopServer.cfg.PeerTimeout) * time.Second)

	for port := cfg.PortStart; port <= cfg.PortEnd; port++ {
		go hopServer.listen(cfg.Protocol, fmt.Sprintf("%s:%d", cfg.ListenAddr, port))
	}

	go hopServer.handleInterface()
	go hopServer.forwardFrames()

	go hopServer.peerTimeoutWatcher()
	hopServer.cleanUp()
	return
}

func (srv *CandyVPNServer) handleInterface() {
	go func() {
		for {
			pbytes := <-srv.toIface
			log.Debug("New Net packet to device")
			_, err := srv.iface.Write(pbytes)
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

func (srv *CandyVPNServer) listen(protocol conn.TransProtocol, addr string) {
	l, err := conn.NewListener(protocol, addr)
	if err != nil {
		log.Errorf("Failed to listen on %s: %s", addr, err.Error())
		return
	}

	defer l.Close()

	for {
		connection, err := l.Accept()
		if err != nil {
			log.Errorf("Server %d close because of %v", addr, err)
			return
		}

		streamK, _ := srv.netStreams.AddConnection(connection)

		go func(streamK string, connection net.Conn) {
			for {
				var plen int
				buf := make([]byte, IFACE_BUFSIZE)
				plen, err = connection.Read(buf)
				if err != nil {
					srv.netStreams.Close(streamK)
					log.Error(err.Error())
					return
				}

				err = srv.netStreams.Input(streamK, buf[:plen])
				if err != nil && err != needMoreData {
					srv.netStreams.Close(streamK)
					return
				}
			}
		}(streamK, connection)
	}
}

func (srv *CandyVPNServer) forwardFrames() {

	srv.pktHandle = map[Protocol](func(*VPNPeer, *HopPacket)){
		HOP_FLG_PING:              srv.handlePing,
		HOP_FLG_PING_ACK:          srv.handlePingAck,
		HOP_FLG_HSH:               srv.handleHandshake,
		HOP_FLG_HSH_ACK:           srv.handleHandshakeAck,
		HOP_FLG_DAT:               srv.handleDataPacket,
		HOP_FLG_FIN:               srv.handleFinish,
	}

	for {
		select {
		case pack := <-srv.fromIface:
			if tcpip.IsIPv4(pack) {
				dest := tcpip.IPv4Packet(pack).DestinationIP().To4()
				log.Debugf("ip dest: %v", dest)

				if peer, found := srv.peers.PeersByIp[dest.String()]; found {
					srv.SendToClient(peer, &DataPacket{Payload:pack})
				} else {
					log.Warningf("client peer(%s) not found", dest.String())
				}

			}

		case inPacket := <-srv.netStreams.InPackets:
			hPack := inPacket.hp
			var peer *VPNPeer
			var found bool
			var err error

			if handle_func, ok := srv.pktHandle[hPack.Proto]; ok {
				peer, found = srv.peers.PeersByID[hPack.Sid]

				if !found && hPack.Proto == HOP_FLG_HSH {
					peer, err = srv.peers.NewPeer(hPack.Sid, inPacket.stream)
					if err != nil {
						log.Errorf("Cant alloc IP from pool %v", err)
					}
				} else if !found {
					continue
				}

				peer.LastSeenTime = time.Now()
				if handle_func != nil {
					handle_func(peer, hPack)
				}

			} else {
				log.Errorf("Unkown flag: %x", hPack.Proto)
			}

		}
	}
}

func (srv *CandyVPNServer) SendToClient(peer *VPNPeer, p AppPacket) {
	hp := NewHopPacket(peer, p)
	log.Debugf("peer: %v", peer)
	srv.netStreams.Output(peer.RandomStream(), hp)
}

func (srv *CandyVPNServer) handlePing(hpeer *VPNPeer, hp *HopPacket) {
	if hpeer.state == HOP_STAT_WORKING {
		srv.SendToClient(hpeer, new(PingAckPacket))
	}
}

func (srv *CandyVPNServer) handlePingAck(hpeer *VPNPeer, hp *HopPacket) {
	return
}

func (srv *CandyVPNServer) handleHandshake(peer *VPNPeer, hp *HopPacket) {
	log.Debugf("assign address %s", peer.Ip)
	atomic.StoreInt32(&peer.state, HOP_STAT_HANDSHAKE)

	size, _ := srv.peers.IpPool.subnet.Mask.Size()

	srv.SendToClient(peer,
		&HandshakeAckPacket{
			Ip:peer.Ip,
			MaskSize:size},
	)
	go func() {
		select {
		case <-peer.hsDone:
			peer.state = HOP_STAT_WORKING
			return
		case <-time.After(8 * time.Second):
			srv.SendToClient(peer, new(FinPacket))
			srv.peers.DeletePeer(peer)
		}
	}()
}

func (srv *CandyVPNServer) handleHandshakeAck(peer *VPNPeer, hp *HopPacket) {
	log.Infof("Client %d Connected", peer.Ip)
	if ok := atomic.CompareAndSwapInt32(&peer.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING); ok {
		close(peer.hsDone)
	}
}

func (srv *CandyVPNServer) handleDataPacket(peer *VPNPeer, hp *HopPacket) {
	if peer.state == HOP_STAT_WORKING {
		srv.toIface <- (hp.packet.(*DataPacket)).Payload
	}
}

func (srv *CandyVPNServer) handleFinish(peer *VPNPeer, hp *HopPacket) {
	log.Infof("Releasing client ip: %d", peer.Ip)
	srv.peers.DeletePeer(peer)
	srv.SendToClient(peer, new(FinAckPacket))
}

func (srv *CandyVPNServer) cleanUp() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)
	<-c

	for _, peer := range srv.peers.PeersByIp {
		srv.SendToClient(peer, new(FinAckPacket))
	}
	os.Exit(0)
}

func (srv *CandyVPNServer) peerTimeoutWatcher() {
	timeout := time.Second * time.Duration(srv.cfg.PeerTimeout)

	for {
		select {
		case <-time.After(timeout):
			for _, peer := range srv.peers.PeersByIp {
				log.Debugf("IP: %v", peer.Ip)
				srv.SendToClient(peer, new(PingPacket))
			}
		case peer := <-srv.peers.PeerTimeout:
			srv.SendToClient(peer, new(FinPacket))
		}
	}
}

