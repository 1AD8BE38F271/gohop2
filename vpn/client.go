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
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
	"github.com/FTwOoO/vpncore/tuntap"
	"github.com/FTwOoO/vpncore/conn"
	"github.com/FTwOoO/go-enc"
	"github.com/FTwOoO/vpncore/routes"
	"github.com/FTwOoO/vpncore/dns"
)

type CandyVPNClient struct {
	cfg        *VPNConfig
	iface      *tuntap.Interface
	router     *routes.RoutesManager
	dnsManager *dns.DNSManager

	peer       *VPNPeer
	toIface    chan []byte
	netStreams PacketStreams
	pktHandle  map[Protocol]func(string, *HopPacket)

	finishAck  chan struct{} //清理时是主动发送FIN包，这个chan只是用来锁定是否收到的FIN的回应
}

func NewClient(cfg *VPNConfig) error {
	var err error

	hopClient := new(CandyVPNClient)
	hopClient.peer = NewVPNPeer(uint32(rand.Int31n(0xFFFFFF)), net.IP{0, 0, 0, 0})
	hopClient.toIface = make(chan []byte, 128)
	hopClient.netStreams = NewPacketStreams()
	hopClient.router, _ = routes.NewRoutesManager()
	hopClient.dnsManager = new(dns.DNSManager)


	hopClient.cfg = cfg
	hopClient.finishAck = make(chan struct{})

	iface, err := tuntap.NewTUN("tun2")
	if err != nil {
		panic(err)
	}
	hopClient.iface = iface

	for port := cfg.PortStart; port <= cfg.PortEnd; port++ {
		server := fmt.Sprintf("%s:%d", cfg.ServerAddr, port)
		fmt.Printf("Connecting to server %s ...\n", server)
		blockConfig := &enc.BlockConfig{Cipher:enc.Cipher(cfg.Cipher), Password:cfg.Password}
		connection, err := conn.Dial(cfg.Protocol, server, blockConfig)

		if err != nil {
			fmt.Println(err)
			continue
		} else {
			hopClient.router.AddRouteToHost(
				hopClient.router.DefaultNic,
				net.ParseIP(cfg.ServerAddr),
				hopClient.router.DefaultGateway)

			streamKey, _ := hopClient.netStreams.AddConnection(connection)
			go hopClient.handleConnection(streamKey)
		}
	}

	wait_handshake:
	for {
		select {
		case <-hopClient.peer.hsDone:
			break wait_handshake
		}
	}

	err = hopClient.router.SetNewGateway(hopClient.iface.Name(), hopClient.iface.IP())
	if err != nil {
		return err
	}

	if cfg.DNS != "" {
		dnsl := []net.IP{net.ParseIP(cfg.DNS)}
		err = hopClient.dnsManager.SetupNewDNS(dnsl)
		if err != nil {
			return err
		}

		for _, dns_ip := range dnsl {
			hopClient.router.AddRouteToHost(hopClient.iface.Name(), dns_ip, hopClient.iface.IP())
		}

	}

	go hopClient.forwardFrames()
	go hopClient.handleInterface()
	hopClient.cleanUp()

	return errors.New("Not expected to exit")
}

func (clt *CandyVPNClient) handleInterface() {
	go func() {
		for {
			packet := <-clt.toIface
			_, err := clt.iface.Write(packet)
			if err != nil {
				log.Error(err.Error())
				return
			}
		}
	}()

	frame := make([]byte, IFACE_BUFSIZE)
	for {
		n, err := clt.iface.Read(frame)
		if err != nil {
			log.Error(err.Error())
			return
		}
		buf := make([]byte, n)
		copy(buf, frame)
		clt.sendToServer(&DataPacket{Payload:buf})
	}
}

func (clt *CandyVPNClient) forwardFrames() {

	clt.pktHandle = map[Protocol](func(string, *HopPacket)){
		HOP_FLG_HSH_ACK: clt.handleHandshakeAck,
		HOP_FLG_PING:    clt.handlePing,
		HOP_FLG_PING_ACK:clt.handlePingAck,
		HOP_FLG_DAT:     clt.handleDataPacket,
		HOP_FLG_FIN_ACK: clt.handleFinishAck,
		HOP_FLG_FIN:     clt.handleFinish,
	}

	for {
		inp := <-clt.netStreams.InPackets
		if handle_func, ok := clt.pktHandle[inp.hp.Proto]; ok {
			fmt.Printf("Got a packet %v", inp.hp)
			handle_func(inp.stream, inp.hp)
		} else {
			log.Errorf("Unkown flag: %x", inp.hp.Proto)
		}
	}
}

func (clt *CandyVPNClient) handleConnection(streamKey string) {

	_, ok := clt.netStreams.Streams[streamKey]
	if !ok {
		return
	}

	connectionDone := make(chan struct{}, 1)

	go func(done  <- chan struct{}) {
		for {
			clt.handeshake()
			select {
			case <-clt.peer.hsDone:
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
				if clt.peer.state == HOP_STAT_WORKING {
					clt.ping()
				}
			case <-done:
				return
			}
		}
	}(connectionDone)

	for {
		err := clt.netStreams.Read(streamKey)
		if err != nil {
			log.Error(err.Error())
			close(connectionDone)
			clt.netStreams.Close(streamKey)
			return
		}
	}
}

func (clt *CandyVPNClient) sendToServer(p AppPacket) {
	hp := NewHopPacket(clt.peer, p)

	//random stream
	stream := ""
	i := int(float32(len(clt.netStreams.Streams)) * rand.Float32())
	for k, _ := range clt.netStreams.Streams {
		if i == 0 {
			stream = k
			break
		} else {
			i--
		}
	}

	clt.netStreams.Write(stream, hp)
}

func (clt *CandyVPNClient) ping() {
	clt.sendToServer(new(PingPacket))
}

func (clt *CandyVPNClient) handeshake() {
	res := atomic.CompareAndSwapInt32(&clt.peer.state, HOP_STAT_INIT, HOP_STAT_HANDSHAKE)
	if res {
		clt.sendToServer(&HandshakePacket{})
	}
}

func (clt *CandyVPNClient) finishSession() {
	atomic.StoreInt32(&clt.peer.state, HOP_STAT_FIN)
	clt.sendToServer(new(FinPacket))
}

func (clt *CandyVPNClient) handlePingAck(stream string, hp *HopPacket) {
	return
}

func (clt *CandyVPNClient) handlePing(stream string, hp *HopPacket) {
	clt.sendToServer(new(PingAckPacket))
}

func (clt *CandyVPNClient) handleHandshakeAck(stream string, hp *HopPacket) {
	if atomic.LoadInt32(&clt.peer.state) == HOP_STAT_HANDSHAKE {

		ip := hp.packet.(*HandshakeAckPacket).Ip
		makeSize := hp.packet.(*HandshakeAckPacket).MaskSize
		ipStr := fmt.Sprintf("%d.%d.%d.%d/%d", ip[0], ip[1], ip[2], ip[3], makeSize)
		ip, subnet, _ := net.ParseCIDR(ipStr)
		clt.peer.Ip = ip

		err := clt.iface.SetupNetwork(ip, *subnet, clt.cfg.MTU)
		if err != nil {
			panic(err)
		}

		res := atomic.CompareAndSwapInt32(&clt.peer.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING)
		if !res {
			log.Errorf("Client state not expected: %d", clt.peer.state)
		}
		close(clt.peer.hsDone)
		clt.sendToServer(&HandshakeAckPacket{Ip:ip, MaskSize:makeSize})

	} else if atomic.LoadInt32(&clt.peer.state) == HOP_STAT_WORKING {
		clt.sendToServer(hp.packet.(*HandshakeAckPacket))
	}
}

func (clt *CandyVPNClient) handleDataPacket(stream string, hp *HopPacket) {
	if clt.peer.state == HOP_STAT_WORKING {
		clt.toIface <- (hp.packet.(*DataPacket)).Payload
	}
}

func (clt *CandyVPNClient) handleFinishAck(stream string, hp *HopPacket) {
	clt.finishAck <- struct{}{}
}

func (clt *CandyVPNClient) handleFinish(stream string, hp *HopPacket) {
	pid := os.Getpid()
	syscall.Kill(pid, syscall.SIGTERM)
}

func (clt *CandyVPNClient) cleanUp() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)
	<-c

	log.Info("Cleaning Up")

	if clt.peer.state != HOP_STAT_INIT {
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
