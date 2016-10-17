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
	"github.com/FTwOoO/vpncore/tcpip"
	"github.com/FTwOoO/vpncore/tuntap"
	"github.com/FTwOoO/go-logger"
	"github.com/FTwOoO/vpncore/enc"
	"github.com/FTwOoO/link/codec"
	"github.com/FTwOoO/link"
	"github.com/FTwOoO/gohop2/protodef"
	"reflect"
	"github.com/golang/protobuf/proto"
	"encoding/binary"
)

const (
	IFACE_BUFSIZE = 2048
	BUF_SIZE = 2048
)

type CandyVPNServer struct {
	cfg       *VPNConfig
	peers     *VPNPeersManager
	iface     *tuntap.Interface
	server    *link.Server

	fromIface chan []byte
	toIface   chan []byte
}

func NewServer(cfg *VPNConfig) (err error) {

	log, err := logger.NewLogger(cfg.LogFile, cfg.LogLevel)
	if err != nil {
		return
	}

	hopServer := new(CandyVPNServer)
	hopServer.fromIface = make(chan []byte, BUF_SIZE)
	hopServer.toIface = make(chan []byte, BUF_SIZE * 4)
	hopServer.cfg = cfg

	iface, err := tuntap.NewTUN("tun1")
	if err != nil {
		return err
	}

	hopServer.iface = iface
	ip, subnet, err := net.ParseCIDR(cfg.Subnet)
	err = iface.SetupNetwork(ip, nil, *subnet, cfg.MTU)
	if err != nil {
		log.Error(err)
		return err
	}

	err = iface.ServerSetupNatRules()
	if err != nil {
		log.Error(err)
		return err
	}

	hopServer.peers = NewVPNPeersManager(subnet, time.Duration(hopServer.cfg.PeerTimeout) * time.Second)

	addr := fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.ServerPort)
	hopServer.server, err = CreateServer(
		cfg.Protocol,
		addr,
		enc.Cipher(cfg.Cipher),
		cfg.Password,
		codec.NewProtobufProtocol(allApplicationMessageTypes),
	)

	if err != nil {
		log.Errorf("Failed to listen on %s: %v", addr, err)
		KillMyself()
	}
	go hopServer.server.Serve(link.HandlerFunc(hopServer.sessionLoop))

	go hopServer.handleInterface()
	go hopServer.forwardFrames()
	go hopServer.peerTimeoutWatcher()

	hopServer.cleanUp()
	return
}

func (srv *CandyVPNServer) handleInterface() {
	go func() {
		for {
			packet := <-srv.toIface
			LogIP4Packet(packet, "To iface packet")
			_, err := srv.iface.Write(packet)
			if err != nil {
				return
			}
		}
	}()

	buf := make([]byte, IFACE_BUFSIZE)
	for {
		n, err := srv.iface.Read(buf)
		if err != nil {
			log.Error(err)
			return
		}
		hpbuf := make([]byte, n)
		copy(hpbuf, buf)
		srv.fromIface <- hpbuf
	}
}

func (srv *CandyVPNServer) forwardFrames() {
	for {
		select {
		case packet := <-srv.fromIface:
			if tcpip.IsIPv4(packet) {
				dest := tcpip.IPv4Packet(packet).DestinationIP().To4()

				peer := srv.peers.GetPeerByIp(dest)
				if peer != nil {
					LogIP4Packet(packet, "From iface packet")
					msg := &protodef.Data{
						Header:&protodef.PacketHeader{Pid:peer.Id, Seq:peer.NextSeq()},
						Payload:packet,
					}

					err := srv.SendToClient(peer, nil, msg)
					if err != nil {
						log.Errorf("send packet to ip %v fail:%v!", dest, err)
					}
				}
			}

		}
	}
}

func (srv *CandyVPNServer) sessionLoop(session *link.Session) {
	log.Debugf("New session:%d", session.ID())

	for {
		req, err := session.Receive()
		if err != nil {
			log.Errorf("Sesscion error on Receive(): %v", err)
			session.Close()
			return
		}

		log.Debugf("Receive a msg with type %s", reflect.TypeOf(req))
		sessionId := session.ID()
		peer := srv.peers.GetPeerBySession(sessionId)
		if peer != nil {
			peer.Touch()
		}

		switch req.(type) {
		case *protodef.Handshake:
			if peer == nil {
				reqmsg := req.(*protodef.Handshake)
				if reqmsg.Header == nil {
					log.Errorf("Null header of handshake")
					continue
				}

				Pid := reqmsg.Header.Pid
				peer, err = srv.peers.NewPeer(Pid)
				if err != nil {
					log.Errorf("Cant alloc IP from pool %v", err)
				}
				srv.peers.AddSessionToPeer(peer, sessionId)
			} else {
				srv.peers.AddSessionToPeer(peer, sessionId)
			}

			log.Debugf("Assign address %s", peer.Ip)
			atomic.StoreInt32(&peer.State, HOP_STAT_HANDSHAKE)

			size, _ := srv.peers.IpPool.Subnet.Mask.Size()

			msg := &protodef.HandshakeAck{
				Header:req.(*protodef.Handshake).Header,
				Ip:binary.BigEndian.Uint32(peer.Ip.To4()),
				ServerIp:binary.BigEndian.Uint32(srv.peers.MyIp.To4()),
				MarkSize:uint32(size),
			}
			err = srv.SendToClient(peer, session, msg)
			if err != nil {
				log.Error(err)
			}

			go func() {
				select {
				case <-peer.HandshakeDone:
					peer.State = HOP_STAT_WORKING
					return
				case <-time.After(8 * time.Second):
					msg := &protodef.Fin{Header:req.(*protodef.Handshake).Header}
					err = srv.SendToClient(peer, session, msg)
					if err != nil {
						log.Error(err)
					}
					srv.peers.DeletePeer(peer)
				}
			}()
		case *protodef.Ping:
			if peer != nil && peer.State == HOP_STAT_WORKING {
				msg := &protodef.PingAck{Header:req.(*protodef.Ping).Header}
				err = srv.SendToClient(peer, session, msg)
			}
		case *protodef.Data:
			if peer != nil && peer.State == HOP_STAT_WORKING {
				srv.toIface <- req.(*protodef.Data).Payload
			}
		case *protodef.Fin:
			if peer != nil {
				log.Infof("Releasing client ip: %v", peer.Ip)
				msg := &protodef.FinAck{Header:req.(*protodef.Fin).Header}
				err = srv.SendToClient(peer, session, msg)
				if err != nil {
					log.Error(err)
				}
				srv.peers.DeletePeer(peer)
			}

		case *protodef.HandshakeAck:
			if peer != nil {
				log.Infof("Client %d[ip %d] Connected", peer.Id, peer.Ip)
				if ok := atomic.CompareAndSwapInt32(&peer.State, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING); ok {
					close(peer.HandshakeDone)
				}
			}
		case *protodef.PingAck:
		case *protodef.DataAck:
		case *protodef.FinAck:
		default:
			log.Errorf("Message type %s that server dont support yet!\n", reflect.TypeOf(req))
		}
	}
}

func (srv *CandyVPNServer) cleanUp() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)
	<-c

	allPeers := srv.peers.GetAllPeers()

	for _, peer := range allPeers {
		msg := &protodef.Fin{
			Header:&protodef.PacketHeader{Pid:peer.Id, Seq:peer.NextSeq()},
		}
		srv.SendToClient(peer, nil, msg)
	}
	os.Exit(0)
}

func (srv *CandyVPNServer) peerTimeoutWatcher() {
	timeout := time.Second * time.Duration(srv.cfg.PeerTimeout)

	for {
		select {
		case <-time.After(timeout):
			allPeers := srv.peers.GetAllPeers()
			for _, peer := range allPeers {
				log.Debugf("Ping %v", peer.Ip)
				msg := &protodef.Ping{
					Header:&protodef.PacketHeader{Pid:peer.Id, Seq:peer.NextSeq()},
				}
				srv.SendToClient(peer, nil, msg)
			}
		case peer := <-srv.peers.PeerTimeout:
			log.Infof("Peer %v timeout", peer.Ip)
			msg := &protodef.Fin{
				Header:&protodef.PacketHeader{Pid:peer.Id, Seq:peer.NextSeq()},
			}
			srv.SendToClient(peer, nil, msg)
			srv.peers.DeletePeer(peer)

		}
	}
}

func (srv *CandyVPNServer) SendToClient(peer *VPNPeer, session *link.Session, msg proto.Message) error {
	if session != nil {
		return session.Send(msg)
	}

	allSessionId := srv.peers.GetPeerSessions(peer)

	if allSessionId == nil || len(allSessionId) == 0 {
		return fmt.Errorf("No active sessions found for peer[%s]", peer.Ip)
	}

	for _, sessionId := range allSessionId {
		session := srv.server.GetSession(sessionId)
		if session != nil {
			err := session.Send(msg)
			if err != nil {
				log.Debug(err)
				continue
			}
			return nil
		}
	}

	return fmt.Errorf("Send msg fail: %v", msg)
}