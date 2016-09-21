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
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
	"github.com/FTwOoO/vpncore/tuntap"
	"github.com/FTwOoO/vpncore/conn"
	"github.com/FTwOoO/go-logger"

)

type CandyVPNClient struct {
	cfg            CandyVPNServerConfig
	iface          *tuntap.Interface
	ip             net.IP
	sid            [4]byte
	state          int32

	toIface        chan []byte
	toNet          chan *HopPacket

	handshakeDone  chan struct{}
	handshakeError chan struct{}
	finishAck      chan byte //清理时是主动发送FIN包，这个chan只是用来锁定是否收到的FIN的回应
	seq            uint32
}

var log logger.Logger


func NewClient(cfg CandyVPNServerConfig) error {
	var err error


	hopClient := new(CandyVPNClient)
	rand.Read(hopClient.sid[:])
	hopClient.toIface = make(chan []byte, 128)
	hopClient.toNet = make(chan *HopPacket, 128)
	hopClient.cfg = cfg
	hopClient.state = HOP_STAT_INIT
	hopClient.handshakeDone = make(chan struct{})
	hopClient.handshakeError = make(chan struct{})
	hopClient.finishAck = make(chan byte)

	iface, err := tuntap.NewTUN("tun1")
	if err != nil {
		return err
	}
	hopClient.iface = iface

	if err != nil {
		panic(err)
	}

	for port := cfg.PortStart; port <= cfg.PortEnd; port++ {
		server := fmt.Sprintf("%s:%d", cfg.ListenAddr, port)
		proto := conn.PROTO_TCP
		go hopClient.connect(proto, server)
	}


	// wait until handshake done
	wait_handshake:
	for {
		select {
		case <-hopClient.handshakeDone:
			log.Info("Handshake Success")
			break wait_handshake
		case <-hopClient.handshakeError:
			return errors.New("Handshake Fail")
		case <-time.After(3 * time.Second):
			log.Info("Handshake Timeout")
			atomic.CompareAndSwapInt32(&hopClient.state, HOP_STAT_HANDSHAKE, HOP_STAT_INIT) //这行代码可以放到
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

	go hopClient.cleanUp()
	hopClient.handleInterface()

	return errors.New("Not expected to exit")
}

func (clt *CandyVPNClient) handleInterface() {
	// network packet to interface
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
		clt.toNet <- NewHopPacket(peer, &DataPacket{Payload:buf})
	}
}

func (clt *CandyVPNClient) connect(proto conn.TransProtocol, serverAddr string) {
	connection, _ := conn.Dial(proto, serverAddr)


	pktHandle := map[byte](func(*net.UDPConn, *HopPacket)){
		HOP_FLG_HSH_ACK: clt.handleHandshakeAck,
		HOP_FLG_HSH_ERR: clt.handleHandshakeError,
		HOP_FLG_PING:               clt.handleHeartbeat,
		HOP_FLG_PING_ACK: clt.handleKnockAck,
		HOP_FLG_DAT:               clt.handleDataPacket,
		HOP_FLG_FIN_ACK: clt.handleFinishAck,
		HOP_FLG_FIN:               clt.handleFinish,
	}

	go func() {
		for {
			//TODO:应该把这个去掉，并且把HANDSHAKE的回复作为该端口唯一可用的判断
			clt.knock(connection)
			n := mrand.Intn(1000)
			time.Sleep(time.Duration(n) * time.Millisecond)
			clt.handeshake(connection)
			select {
			case <-clt.handshakeDone:
			//这个handshakeDone只有一个，一收到一个handshake回应包就close了
			//所以这里不是每个连接都会无限重试
				return
			case <-time.After(5 * time.Second):
				log.Debug("Handshake timeout, retry")
			}
		}
	}()

	go func() {
		var intval time.Duration

		if clt.cfg.Heartbeat_interval <= 0 {
			intval = time.Second * 30
		} else {
			intval = time.Second * time.Duration(clt.cfg.Heartbeat_interval)
		}
		for {
			time.Sleep(intval)
			if clt.state == HOP_STAT_WORKING {
				clt.knock(connection)
			}
		}
	}()

	// add route through net gateway
	if udpAddr, ok := connection.RemoteAddr().(*net.UDPAddr); ok {
		srvIP := udpAddr.IP.To4()
		if srvIP != nil {
			clt.iface.Router().AddRouteToHost(clt.iface.DefaultNic(), srvIP, clt.iface.DefaultGateway())
		}
	}



	// forward iface frames to network
	go func() {
		for {
			hp := <-clt.toNet
			hp.setSid(clt.sid)
			log.Debugf("send packet")

			connection.Write(hp.Pack())
		}
	}()

	buf := make([]byte, IFACE_BUFSIZE)
	for {
		n, err := connection.Read(buf)
		log.Debugf("New incomming packet, len: %d", n)
		if err != nil {
			log.Error(err.Error())
			continue
		}

		hp, err := unpackHopPacket(buf[:n])
		if err != nil {
			log.Debug("Error depacketing")
			continue
		}

		log.Debug("New incomming hop packet: %s", hp.String())
		if handle_func, ok := pktHandle[hp.Flag]; ok {
			handle_func(connection, hp)
		} else {
			log.Errorf("Unkown flag: %x", hp.Flag)
		}
	}
}

func (clt *CandyVPNClient) Seq() uint32 {
	return atomic.AddUint32(&clt.seq, 1)
}

func (clt *CandyVPNClient) toServer(u *net.UDPConn, flag byte, payload []byte, noise bool) {
	hp := new(HopPacket)
	hp.Flag = flag
	hp.Seq = clt.Seq()
	hp.setPayload(payload)
	if noise {
		hp.addNoise(mrand.Intn(MTU - 64 - len(payload)))
	}
	u.Write(hp.Pack())
}

// knock server port or heartbeat
func (clt *CandyVPNClient) knock(u *net.UDPConn) {
	clt.toServer(u, HOP_FLG_PSH, clt.sid[:], true)
}

// handshake with server
func (clt *CandyVPNClient) handeshake(u *net.UDPConn) {
	res := atomic.CompareAndSwapInt32(&clt.state, HOP_STAT_INIT, HOP_STAT_HANDSHAKE)

	if res {
		log.Info("start handeshaking")
		clt.toServer(u, HOP_FLG_HSH, clt.sid[:], true)
	}
}

// finish session
func (clt *CandyVPNClient) finishSession() {
	log.Info("Finishing Session")
	atomic.StoreInt32(&clt.state, HOP_STAT_FIN)
	hp := new(HopPacket)
	hp.Flag = HOP_FLG_FIN
	hp.setPayload(clt.sid[:])
	hp.Seq = clt.Seq()
	clt.toNet <- hp

}

// heartbeat ack
func (clt *CandyVPNClient) handleKnockAck(u *net.UDPConn, hp *HopPacket) {
	return
}

// heartbeat ack
func (clt *CandyVPNClient) handleHeartbeat(u *net.UDPConn, hp *HopPacket) {
	log.Debug("Heartbeat from server")
	clt.toServer(u, HOP_FLG_PSH | HOP_FLG_ACK, clt.sid[:], true)
}

// handle handeshake ack
func (clt *CandyVPNClient) handleHandshakeAck(u *net.UDPConn, hp *HopPacket) {
	if atomic.LoadInt32(&clt.state) == HOP_STAT_HANDSHAKE {
		proto_version := hp.payload[0]
		if proto_version != HOP_PROTO_VERSION {
			log.Error("Incompatible protocol version!")
			os.Exit(1)
		}

		by := hp.payload[1:6]
		ipStr := fmt.Sprintf("%d.%d.%d.%d/%d", by[0], by[1], by[2], by[3], by[4])

		ip, subnet, _ := net.ParseCIDR(ipStr)

		err := clt.iface.SetupNetwork(ip, *subnet, MTU)
		if err != nil {
			panic(err)
		}

		res := atomic.CompareAndSwapInt32(&clt.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING)
		if !res {
			log.Errorf("Client state not expected: %d", clt.state)
		}
		log.Info("Session Initialized")
		close(clt.handshakeDone)
	}

	log.Debug("Handshake Ack to Server")
	clt.toServer(u, HOP_FLG_ACK, clt.sid[:], true)
}

// handle handshake fail
func (clt *CandyVPNClient) handleHandshakeError(u *net.UDPConn, hp *HopPacket) {
	close(clt.handshakeError)
}

// handle data packet
func (clt *CandyVPNClient) handleDataPacket(u *net.UDPConn, hp *HopPacket) {
	clt.recvBuf.Push(hp)
}

// handle finish ack
func (clt *CandyVPNClient) handleFinishAck(u *net.UDPConn, hp *HopPacket) {
	clt.finishAck <- byte(1)
}

// handle finish
func (clt *CandyVPNClient) handleFinish(u *net.UDPConn, hp *HopPacket) {
	log.Info("Finish")
	pid := os.Getpid()
	syscall.Kill(pid, syscall.SIGTERM)
}

func (clt *CandyVPNClient) cleanUp() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)
	<-c

	log.Info("Cleaning Up")
	timeout := time.After(3 * time.Second)
	if clt.state != HOP_STAT_INIT {
		clt.finishSession()
	}

	select {
	case <-clt.finishAck:
		log.Info("Finish Acknowledged")
	case <-timeout:
		log.Info("Timeout, give up")
	}

	// delete all routes and reset default gateway
	clt.iface.Destroy()
	os.Exit(0)
}
