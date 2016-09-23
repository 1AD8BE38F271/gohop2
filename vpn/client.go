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
)

type CandyVPNClient struct {
	cfg           CandyVPNServerConfig

	iface         *tuntap.Interface
	peer          *VPNPeer
	toIface       chan []byte
	netStreams    PacketStreams

	pktHandle     map[Protocol]func(string, *HopPacket)

	handshakeDone chan struct{}
	finishAck     chan struct{} //清理时是主动发送FIN包，这个chan只是用来锁定是否收到的FIN的回应
}

func NewClient(cfg CandyVPNServerConfig) error {
	var err error

	hopClient := new(CandyVPNClient)
	hopClient.peer = NewVPNPeer(uint32(rand.Int31n(0xFFFFFF)), net.IP{0, 0, 0, 0})
	hopClient.toIface = make(chan []byte, 128)
	hopClient.netStreams = NewPacketStreams()

	hopClient.cfg = cfg
	hopClient.handshakeDone = make(chan struct{})
	hopClient.finishAck = make(chan struct{})

	iface, err := tuntap.NewTUN("tun1")
	if err != nil {
		return err
	}
	hopClient.iface = iface

	if err != nil {
		panic(err)
	}

	for port := cfg.PortStart; port <= cfg.PortEnd; port++ {
		server := fmt.Sprintf("%s:%d", cfg.ServerAddr, port)
		connection, err := hopClient.connect(cfg.Protocol, server)

		if err != nil {
			continue
		} else {
			hopClient.iface.Router().AddRouteToHost(
				hopClient.iface.DefaultNic(),
				net.ParseIP(cfg.ServerAddr),
				hopClient.iface.DefaultGateway())

			streamKey, _ := hopClient.netStreams.AddConnection(connection)
			hopClient.peer.AddStream(streamKey)
			go hopClient.handleConnection(streamKey)
		}
	}


	// wait until handshake done
	wait_handshake:
	for {
		select {
		case <-hopClient.handshakeDone:
			break wait_handshake
		}
	}

	err = iface.ClientRedirectGateway()
	if err != nil {
		return err
	}
	if cfg.DNS != nil {
		err = iface.ClientSetupNewDNS(cfg.DNS)
		if err != nil {
			return err
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
			handle_func(inp.stream, inp.hp)
		} else {
			log.Errorf("Unkown flag: %x", inp.hp.Proto)
		}
	}
}

func (clt *CandyVPNClient) connect(proto conn.TransProtocol, serverAddr string) (connection net.Conn, err error) {
	connection, err = conn.Dial(proto, serverAddr)
	if err != nil {
		return
	}

	return
}

func (clt *CandyVPNClient) handleConnection(streamKey string) {

	stream, ok := clt.netStreams.Streams[streamKey]
	if !ok {
		return
	}

	connection := stream.Connection

	go func() {
		for {
			clt.handeshake()
			select {
			case <-clt.handshakeDone:
				return
			case <-time.After(5 * time.Second):
				log.Debug("Handshake timeout, retry")
			}
		}
	}()

	go func() {
		intval := time.Second * 30

		for {
			time.Sleep(intval)
			if clt.peer.state == HOP_STAT_WORKING {
				clt.ping()
			}
		}
	}()

	buf := make([]byte, IFACE_BUFSIZE)
	for {
		n, err := connection.Read(buf)
		log.Debugf("New incomming packet, len: %d", n)
		if err != nil {
			log.Error(err.Error())
			clt.netStreams.Close(streamKey)
			return
		}

		err = clt.netStreams.Input(streamKey, buf[:n])
		if err != nil {
			clt.netStreams.Close(streamKey)
			return
		}
	}
}

func (clt *CandyVPNClient) sendToServer(p AppPacket) {
	hp := NewHopPacket(clt.peer, p)
	clt.netStreams.Output(clt.peer.RandomStream(), hp)
}

func (clt *CandyVPNClient) ping() {
	clt.sendToServer(new(PingPacket))
}

func (clt *CandyVPNClient) handeshake() {
	res := atomic.CompareAndSwapInt32(&clt.peer.state, HOP_STAT_INIT, HOP_STAT_HANDSHAKE)
	if res {
		clt.sendToServer(
			&HandshakeAckPacket{
				Ip:clt.peer.Ip,
				MaskSize:0},
		)
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

		err := clt.iface.SetupNetwork(ip, *subnet, clt.cfg.MTU)
		if err != nil {
			panic(err)
		}

		res := atomic.CompareAndSwapInt32(&clt.peer.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING)
		if !res {
			log.Errorf("Client state not expected: %d", clt.peer.state)
		}
		close(clt.handshakeDone)
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

	clt.iface.Destroy()
	os.Exit(0)
}
