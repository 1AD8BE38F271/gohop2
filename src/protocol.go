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
 * Author:  FTwOoO <booobooob@gmail.com>
 */


package hop

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"net"
)

type Protocol uint32

const (
	HOP_ACK_MARK byte = 0x01 // acknowledge
	HOP_PROTO_VERSION byte = 0x01 // protocol version


	HOP_FLG_PING Protocol = 0x80
	HOP_FLG_PING_ACK Protocol = HOP_ACK_MARK | HOP_FLG_PING

	HOP_FLG_HSH Protocol = 0x40
	HOP_FLG_HSH_ACK Protocol = HOP_ACK_MARK | HOP_FLG_HSH

	HOP_FLG_FIN Protocol = 0x20
	HOP_FLG_FIN_ACK Protocol = HOP_ACK_MARK | HOP_FLG_FIN

	HOP_FLG_DAT Protocol = 0x10
	HOP_FLG_DAT_ACK Protocol = HOP_ACK_MARK | HOP_FLG_DAT

	HOP_STAT_INIT int32 = iota // initing
	HOP_STAT_HANDSHAKE              // handeshaking
	HOP_STAT_WORKING                // working
	HOP_STAT_FIN                    // finishing
)

type AppPacket interface {
	Pack() []byte
	Unpack(buf *bytes.Buffer) error
	String() string
	Protocol() Protocol
}

type HandshakePacket struct{}

func (p *HandshakePacket) Unpack(buf *bytes.Buffer) error {
	return nil
}

func (p *HandshakePacket) Protocol() Protocol {
	return HOP_FLG_HSH
}

func (p *HandshakePacket) String() string {
	return "HandshakePacket"
}

type HandshakeAckPacket struct {
	Ip       net.IP
	MaskSize int
}

func (p *HandshakeAckPacket) Pack() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, len(p)))
	binary.Write(buf, binary.BigEndian, p)
	return buf.Bytes()
}

func (p *HandshakeAckPacket) Protocol() Protocol {
	return HOP_FLG_HSH_ACK
}

func (p *HandshakeAckPacket) String() string {
	return fmt.Sprintf("IP:%v, MaskSize:%d", p.Ip.String(), p.MaskSize)
}

type PingPacket struct {
}

func (p *PingPacket) Unpack(buf *bytes.Buffer) error {
	return nil
}

func (p *PingPacket) Protocol() Protocol {
	return HOP_FLG_PING
}



type PingAckPacket struct {
}

func (p *PingAckPacket) Pack() []byte {
	return []byte{}
}

func (p *PingAckPacket) Protocol() Protocol {
	return HOP_FLG_PING_ACK
}

type FinPacket struct {
}

func (p *FinPacket) Unpack(buf *bytes.Buffer) error {
	return nil
}

func (p *FinPacket) Pack() []byte {
	return []byte{}
}

func (p *FinPacket) Protocol() Protocol {
	return HOP_FLG_FIN
}



type FinAckPacket struct {
}

func (p *FinAckPacket) Unpack(buf *bytes.Buffer) error {
	return nil
}

func (p *FinAckPacket) Pack() []byte {
	return []byte{}
}

func (p *FinAckPacket) Protocol() Protocol {
	return HOP_FLG_FIN_ACK
}



type DataPacket struct {
	Dlen    uint16
	Payload []byte
}

func (p *DataPacket) Unpack(buf *bytes.Buffer) error {
	return nil
}

func (p *DataPacket) Pack() []byte {
	p.Dlen = uint16(len(p.Payload))

	buf := bytes.NewBuffer(make([]byte, 0, len(4 + p.Dlen)))
	binary.Write(buf, binary.BigEndian, p.Dlen)
	binary.Write(buf, binary.BigEndian, p.Payload)
	return buf.Bytes()
}

func (p *DataPacket) Protocol() Protocol {
	return HOP_FLG_DAT
}



type HopPacket struct {
	Sid        uint32
	Proto      uint32
	Seq        uint32
	Dlen       uint16 //发送前要设置
	DataPacket AppPacket
}

func (p *HopPacket) Pack() []byte {
	Payload := p.DataPacket.Pack()
	p.Dlen = uint16(len(Payload))

	buf := bytes.NewBuffer(make([]byte, 0, len(16 + p.Dlen)))
	binary.Write(buf, binary.BigEndian, p.Sid)
	binary.Write(buf, binary.BigEndian, p.Proto)
	binary.Write(buf, binary.BigEndian, p.Seq)
	binary.Write(buf, binary.BigEndian, p.Dlen)
	binary.Write(buf, binary.BigEndian, Payload)

	b := buf.Bytes()
	return b
}

func (p *HopPacket) String() string {
	flag := make([]string, 0, 8)
	if (p.Proto == 0) {
		flag = append(flag, "DAT")
	}
	if p.Proto & HOP_FLG_PING != 0 {
		flag = append(flag, "PING")
	}
	if p.Proto & HOP_FLG_HSH != 0 {
		flag = append(flag, "HSH")
	}
	if p.Proto & HOP_FLG_FIN != 0 {
		flag = append(flag, "FIN")
	}
	if p.Proto & HOP_ACK_MARK != 0 {
		flag = append(flag, "ACK")
	}

	sflag := strings.Join(flag, " | ")
	return fmt.Sprintf(
		"{Flag: %s, Seq: %d, Dlen: %d, Payload: %s}",
		sflag, p.Seq, p.Dlen, p.DataPacket.String(),
	)
}

func NewHopPacket(peer *VPNPeer, p *AppPacket) *HopPacket {
	hp := new(HopPacket)
	hp.Sid = peer.Id
	hp.Seq = peer.NextSeq()
	hp.Proto = p.Protocol()
	hp.DataPacket = *p
	return hp
}

func unpackHopPacket(b []byte) (p *HopPacket, remainBytes uint, err error) {
	frame := make([]byte, len(b))
	copy(frame, b)

	buf := bytes.NewBuffer(frame)
	p = new(HopPacket)

	if err = binary.Read(buf, binary.BigEndian, &p.Sid); err != nil {
		return
	}

	if err = binary.Read(buf, binary.BigEndian, &p.Proto); err != nil {
		return
	}

	if err = binary.Read(buf, binary.BigEndian, &p.Seq); err != nil {
		return
	}

	if err = binary.Read(buf, binary.BigEndian, &p.Dlen); err != nil {
		return
	}

	var datapacket AppPacket
	if p.Proto == HOP_FLG_HSH {
		datapacket = new(HandshakePacket)
	}

	if err = datapacket.Unpack(buf); err != nil {
		return
	}

	remainBytes = len(buf)
	return p, remainBytes, nil
}
