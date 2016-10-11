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
	"github.com/FTwOoO/vpncore/dns"
	"github.com/FTwOoO/vpncore/tuntap"
	"github.com/FTwOoO/vpncore/enc"
	"github.com/FTwOoO/link/codec"
	"github.com/FTwOoO/link"
	"github.com/FTwOoO/vpncore/routes"
	"github.com/FTwOoO/gohop2/protodef"
	"reflect"
	"github.com/golang/protobuf/proto"
	"encoding/binary"
	"github.com/FTwOoO/vpncore/tcpip"
	"math/rand"
)

type CandyVPNClient struct {
	cfg        *VPNConfig
	iface      *tuntap.Interface
	router     *routes.RoutesManager
	dnsManager *dns.DNSManager
	sessions   []*link.Session

	peer       *VPNPeer
	toIface    chan []byte

	finishAck  chan struct{} //清理时是主动发送FIN包，这个chan只是用来锁定是否收到的FIN的回应
}

func NewClient(cfg *VPNConfig) error {
	var err error

	hopClient := new(CandyVPNClient)
	hopClient.peer = NewVPNPeer(rand.Uint32(), net.IP{0, 0, 0, 0})
	hopClient.toIface = make(chan []byte, 128)
	hopClient.router, _ = routes.NewRoutesManager()
	hopClient.dnsManager = new(dns.DNSManager)
	hopClient.sessions = []*link.Session{}

	hopClient.cfg = cfg
	hopClient.finishAck = make(chan struct{})

	iface, err := tuntap.NewTUN("tun2")
	if err != nil {
		panic(err)
	}
	hopClient.iface = iface

	serverAddr := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)
	fmt.Printf("Connecting to server %s ...\n", serverAddr)

	session, err := Connect(
		cfg.Protocol,
		serverAddr,
		enc.Cipher(cfg.Cipher),
		cfg.Password,
		codec.NewProtobufProtocol(hopClient, allApplicationProtocols),
		0x100)

	if err != nil {
		panic(err)
	}

	go hopClient.cleanUp()

	hopClient.router.AddRouteToHost(
		hopClient.router.DefaultNic,
		net.ParseIP(cfg.ServerAddr),
		hopClient.router.DefaultGateway)

	go hopClient.handleConnection(session)
	hopClient.sessions = append(hopClient.sessions, session)

	wait_handshake:
	for {
		select {
		case <-hopClient.peer.HandshakeDone:
			break wait_handshake
		}
	}

	err = hopClient.router.SetNewGateway(hopClient.iface.Name(), hopClient.iface.IP())
	if err != nil {
		KillMyself()
		return nil
	}

	if cfg.DNS != "" {
		dnsl := []net.IP{net.ParseIP(cfg.DNS)}
		err = hopClient.dnsManager.SetupNewDNS(dnsl)
		if err != nil {
			log.Error(err)
			KillMyself()
			return nil
		}

		for _, dns_ip := range dnsl {
			hopClient.router.AddRouteToHost(hopClient.iface.Name(), dns_ip, hopClient.iface.IP())
		}
	}

	hopClient.handleInterface()
	return nil
}

func (clt *CandyVPNClient) handleInterface() {
	go func() {
		for {
			packet := <-clt.toIface
			_, err := clt.iface.Write(packet)
			if err != nil {
				log.Error(err)
				return
			}
		}
	}()

	frame := make([]byte, IFACE_BUFSIZE)
	for {
		n, err := clt.iface.Read(frame)
		if err != nil {
			log.Error(err)
			return
		}
		buf := make([]byte, n)
		copy(buf, frame)
		dest := tcpip.IPv4Packet(buf).DestinationIP().To4()
		log.Debugf("from iface packet: ip dest %v", dest)

		clt.sendToServer(&protodef.Data{Header:&protodef.PacketHeader{Pid:clt.peer.Id, Seq:clt.peer.NextSeq()}, Payload:buf}, nil)
	}
}

func (clt *CandyVPNClient) handleConnection(session *link.Session) {
	log.Infof("Connected to server %d\n", session.ID())

	connectionDone := make(chan struct{}, 1)

	go func(done  <- chan struct{}) {
		for {
			clt.handeshake()
			select {
			case <-clt.peer.HandshakeDone:
				return
			case <-time.After(5 * time.Second):
				log.Debug("Handshake timeout, retry")
			case <-done:
				return
			}
		}
	}(connectionDone)

	go func(done  <- chan struct{}) {
		for {
			select {
			case <-time.After((clt.cfg.PeerTimeout / 2) * time.Second):
				if clt.peer.State == HOP_STAT_WORKING {
					clt.ping()
				}
			case <-done:
				return
			}
		}
	}(connectionDone)

	for {
		rsp, err := session.Receive()
		if err != nil {
			log.Error(err)
			return
		}

		log.Debugf("Receive a msg with type %s", reflect.TypeOf(rsp))

		switch rsp.(type) {
		case *protodef.Handshake:

		case *protodef.Ping:
			clt.sendToServer(&protodef.PingAck{Header:&protodef.PacketHeader{Pid:clt.peer.Id, Seq:clt.peer.NextSeq()}}, session)

		case *protodef.Data:
			if clt.peer.State == HOP_STAT_WORKING {
				ipPacket := (rsp.(*protodef.Data)).Payload
				dest := tcpip.IPv4Packet(ipPacket).DestinationIP().To4()
				log.Debugf("from net packet: ip dest %v", dest)
				clt.toIface <- ipPacket
			}
		case *protodef.Fin:
			KillMyself()

		case *protodef.HandshakeAck:
			if atomic.LoadInt32(&clt.peer.State) == HOP_STAT_HANDSHAKE {

				ip := make([]byte, 4)
				serverIp := make([]byte, 4)
				binary.BigEndian.PutUint32(ip, rsp.(*protodef.HandshakeAck).Ip)
				binary.BigEndian.PutUint32(serverIp, rsp.(*protodef.HandshakeAck).ServerIp)
				makeSize := rsp.(*protodef.HandshakeAck).MarkSize
				ipStr := fmt.Sprintf("%d.%d.%d.%d/%d", ip[0], ip[1], ip[2], ip[3], makeSize)
				ip, subnet, _ := net.ParseCIDR(ipStr)
				clt.peer.Ip = ip

				err := clt.iface.SetupNetwork(ip, serverIp, *subnet, clt.cfg.MTU)
				if err != nil {
					log.Error(err)
					KillMyself()
				}

				res := atomic.CompareAndSwapInt32(&clt.peer.State, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING)
				if !res {
					log.Errorf("Client state is not HOP_STAT_HANDSHAKE: %d", clt.peer.State)
				}
				close(clt.peer.HandshakeDone)
				clt.sendToServer(rsp.(*protodef.HandshakeAck), session)

			} else if atomic.LoadInt32(&clt.peer.State) == HOP_STAT_WORKING {
				clt.sendToServer(rsp.(*protodef.HandshakeAck), session)
			}

		case *protodef.PingAck:
		case *protodef.DataAck:
		case *protodef.FinAck:
			clt.finishAck <- struct{}{}

		default:
			log.Errorf("Message type is %s that server dont support yet!\n", reflect.TypeOf(rsp))
		}
	}
}

func (clt *CandyVPNClient) ping() {
	log.Debug("send ping")
	clt.sendToServer(&protodef.Ping{Header:&protodef.PacketHeader{Pid:clt.peer.Id, Seq:clt.peer.NextSeq()}}, nil)
}

func (clt *CandyVPNClient) handeshake() {
	res := atomic.CompareAndSwapInt32(&clt.peer.State, HOP_STAT_INIT, HOP_STAT_HANDSHAKE)
	if res {
		log.Debug("send handhake")
		clt.sendToServer(&protodef.Handshake{Header:&protodef.PacketHeader{Pid:clt.peer.Id, Seq:clt.peer.NextSeq()}}, nil)
	}
}

func (clt *CandyVPNClient) finishSession() {
	atomic.StoreInt32(&clt.peer.State, HOP_STAT_FIN)
	clt.sendToServer(&protodef.Fin{Header:&protodef.PacketHeader{Pid:clt.peer.Id, Seq:clt.peer.NextSeq()}}, nil)
}

func (clt *CandyVPNClient) sendToServer(msg proto.Message, session *link.Session) error {

	if session != nil {
		return session.Send(msg)
	}

	for _, session := range clt.sessions {
		if session != nil {
			err := session.Send(msg)
			if err != nil {
				log.Error(err)
				continue
			}
			return nil
		}
	}

	return fmt.Errorf("Send msg fail: %v", msg)

}

func (clt *CandyVPNClient) cleanUp() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)
	<-c
	log.Info("Cleaning Up before exit...")

	if clt.peer.State != HOP_STAT_INIT {
		clt.finishSession()
	}

	select {
	case <-clt.finishAck:
		log.Info("Finish Acknowledged")
	case <-time.After(3 * time.Second):
		log.Info("Timeout, give up")
	}

	clt.iface.Close()
	clt.dnsManager.RestoreDNS()
	clt.router.Destroy()
	os.Exit(0)
}
