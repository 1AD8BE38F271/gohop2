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
	client      *link.Client
	cfg         *VPNConfig
	iface       *tuntap.Interface
	router      *routes.RoutesManager
	dnsManager  *dns.DNSManager

	peer        *VPNPeer
	toIface     chan []byte

	finishAck   chan struct{} //清理时是主动发送FIN包，这个chan只是用来锁定是否收到的FIN的回应
	waitCleanup chan struct{}
}

func NewClient(cfg *VPNConfig) error {
	var err error

	hopClient := new(CandyVPNClient)
	hopClient.peer = NewVPNPeer(rand.Uint32(), net.IP{0, 0, 0, 0})
	hopClient.toIface = make(chan []byte, 128)
	hopClient.router, _ = routes.NewRoutesManager()
	hopClient.dnsManager = new(dns.DNSManager)

	hopClient.cfg = cfg
	hopClient.finishAck = make(chan struct{})
	hopClient.waitCleanup = make(chan struct{})


	// 1. Setup Tun interface
	iface, err := tuntap.NewTUN("tun2")
	if err != nil {
		panic(err)
	} else {
		hopClient.iface = iface
	}


	// 2. Add direct route for VPN
	go hopClient.cleanUp()

	hopClient.router.AddRouteToHost(
		hopClient.router.DefaultNic,
		net.ParseIP(cfg.ServerAddr),
		hopClient.router.DefaultGateway)

	// 3. Setup the client to server connection
	serverAddr := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)
	hopClient.client, err = CreateClient(
		cfg.Protocol,
		serverAddr,
		enc.Cipher(cfg.Cipher),
		cfg.Password,
		codec.NewProtobufProtocol(allApplicationMessageTypes),
	)

	if err != nil {
		panic(err)
	}

	// 4. Start handshake with server
	go hopClient.client.Serve(link.HandlerFunc(hopClient.handleSession))
	hopClient.startClient()

	// 5. Setup the network for VPN interface to route all traffic though VPN
	err = hopClient.router.SetNewGateway(hopClient.iface.Name(), hopClient.iface.IP())
	if err != nil {
		KillMyself()
		return nil
	}

	// 6. Setup DNS
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

	go hopClient.handleInterface()

	<-hopClient.waitCleanup
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
			log.Errorf("Read from iface error %v", err)
			return
		}
		buf := make([]byte, n)
		copy(buf, frame)
		dest := tcpip.IPv4Packet(buf).DestinationIP().To4()
		log.Debugf("from iface packet: ip dest %v", dest)

		clt.sendToServer(&protodef.Data{Header:&protodef.PacketHeader{Pid:clt.peer.Id, Seq:clt.peer.NextSeq()}, Payload:buf}, nil)
	}
}

func (clt *CandyVPNClient) startClient() {

	for {
		clt.handeshake()
		select {
		case <-clt.peer.HandshakeDone:
			return
		case <-time.After(5 * time.Second):
			log.Debug("Handshake timeout, retry")
		case <-clt.waitCleanup:
			return
		}
	}

	go func() {
		for {
			select {
			case <-time.After((clt.cfg.PeerTimeout / 2) * time.Second):
				if clt.peer.State == HOP_STAT_WORKING {
					clt.ping()
				} else if clt.peer.State == HOP_STAT_FIN {
					return
				}
			case <-clt.waitCleanup:
				return
			}
		}
	}()
}

func (clt *CandyVPNClient) handleSession(session *link.Session) {
	log.Infof("Session[%d] connected to server \n", session.ID())

	for {
		rsp, err := session.Receive()
		if err != nil {
			log.Error(err)
			session.Close()
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
			close(clt.finishAck)

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

	session, err := clt.client.GetSession()
	if err != nil {
		log.Error("Get session fail!")
		return err
	}

	return session.Send(msg)
}

func (clt *CandyVPNClient) cleanUp() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGQUIT, os.Interrupt, os.Kill)
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

	clt.client.Stop()

	log.Info("Destroy iface")
	clt.iface.Close()
	log.Info("Restore DNS")
	clt.dnsManager.RestoreDNS()
	log.Info("Restore routes")
	clt.router.Destroy()
	close(clt.waitCleanup)
}
