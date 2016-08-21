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
	"net"
	"strings"
	"github.com/FTwOoO/go-enc"
	"crypto/cipher"
)

var cipher enc.BlockCrypt

const (
	HOP_FLG_PSH byte = 0x80 // port knocking and heartbeat
	HOP_FLG_HSH byte = 0x40 // handshaking
	HOP_FLG_FIN byte = 0x20 // finish session
	HOP_FLG_MFR byte = 0x08 // more fragments
	HOP_FLG_ACK byte = 0x04 // acknowledge
	HOP_FLG_DAT byte = 0x00 // acknowledge

	HOP_STAT_INIT int32 = iota // initing
	HOP_STAT_HANDSHAKE              // handeshaking
	HOP_STAT_WORKING                // working
	HOP_STAT_FIN                    // finishing

	HOP_PROTO_VERSION byte = 0x01 // protocol version
)

type hopPacketHeader struct {
	Flag byte
	Seq  uint32
	Sid  uint32 //会话ID
	Dlen uint16 //发送前要设置
}

func (p hopPacketHeader) String() string {
	flag := make([]string, 0, 8)
	if (p.Flag ^ HOP_FLG_MFR == 0) || (p.Flag == 0) {
		flag = append(flag, "DAT")
	}
	if p.Flag & HOP_FLG_PSH != 0 {
		flag = append(flag, "PSH")
	}
	if p.Flag & HOP_FLG_HSH != 0 {
		flag = append(flag, "HSH")
	}
	if p.Flag & HOP_FLG_FIN != 0 {
		flag = append(flag, "FIN")
	}
	if p.Flag & HOP_FLG_ACK != 0 {
		flag = append(flag, "ACK")
	}
	if p.Flag & HOP_FLG_MFR != 0 {
		flag = append(flag, "MFR")
	}

	sflag := strings.Join(flag, " | ")
	return fmt.Sprintf(
		"{Flag: %s, Seq: %d, Dlen: %d}",
		sflag, p.Seq, p.Dlen,
	)
}

type HopPacket struct {
	hopPacketHeader
	Payload []byte
	Noise   []byte
}

func (p *HopPacket) Pack() []byte {
	p.Dlen = uint16(len(p.Payload))

	buf := bytes.NewBuffer(make([]byte, 0, p.bufSize()))
	binary.Write(buf, binary.BigEndian, p.hopPacketHeader)
	buf.Write(p.Payload)
	buf.Write(p.Noise)

	b := buf.Bytes()
	bout := make([]byte, len(b))
	cipher.Encrypt(bout, b)

	return bout
}

func (p *HopPacket) bufSize() int {
	return 16 + len(p.Payload) + len(p.Noise)
}

func (p *HopPacket) setSid(sid [4]byte) {
	p.Sid = binary.BigEndian.Uint32(sid[:])
}

func (p *HopPacket) String() string {
	return fmt.Sprintf(
		"{%v, Payload: %v, Noise: %v}",
		p.hopPacketHeader, p.Payload, p.Noise,
	)
}

func unpackHopPacket(b []byte) (*HopPacket, error) {
	frame := make([]byte, len(b))
	cipher.Decrypt(frame, b)

	buf := bytes.NewBuffer(frame)
	p := new(HopPacket)
	binary.Read(buf, binary.BigEndian, &p.hopPacketHeader)
	p.Payload = make([]byte, p.Dlen)
	buf.Read(p.Payload)
	return p, nil
}

func udpAddrHash(a *net.UDPAddr) [6]byte {
	var b [6]byte
	copy(b[:4], []byte(a.IP)[:4])
	p := uint16(a.Port)
	b[4] = byte((p >> 8) & 0xFF)
	b[5] = byte(p & 0xFF)
	return b
}

type hUDPAddr struct {
	u    *net.UDPAddr
	hash [6]byte
}

func newhUDPAddr(a *net.UDPAddr) *hUDPAddr {
	return &hUDPAddr{a, udpAddrHash(a)}
}

