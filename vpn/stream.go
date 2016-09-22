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


package vpn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"errors"
)

var needMoreData = errors.New("need more data")

type Stream struct {
	Connection net.Conn
	InBuf      []byte
	Len        uint
}

func NewStream(c net.Conn) *Stream {
	s := Stream{Connection:c}
	s.InBuf = make([]byte, BUF_SIZE)
	return &s
}

func (s *Stream) GetKey() string {
	return s.Connection.RemoteAddr().String()
}

func (s *Stream) Input(data []byte) error {
	if int(s.Len) + len(data) > BUF_SIZE {
		return fmt.Errorf("Incomming data exceed buf size %d!", BUF_SIZE)
	}

	copy(s.InBuf[s.Len:], data)
	s.Len += uint(len(data))
	return nil
}

func (s *Stream) Unpack() (p *HopPacket, err error) {
	p, remainBytes, err := s.tryUnpackHopPacket(s.InBuf)
	if err != nil {
		return
	}

	if remainBytes > 0 {
		copy(s.InBuf[:], s.InBuf[uint(s.Len) - remainBytes:])
		s.Len = remainBytes
	} else {
		s.Len = 0
	}

	return
}

func (s *Stream) tryUnpackHopPacket(b []byte) (p *HopPacket, remainBytes uint, err error) {
	if uint32(len(b)) < p.HeaderSize() + p.Dlen {
		return nil, 0, needMoreData
	}

	buf := bytes.NewBuffer(b)
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

	remainBytes = (uint)(buf.Len())
	return p, remainBytes, nil
}

type InPacket struct {
	hp     *HopPacket
	stream string
}

type PacketStreams struct {
	Streams   map[string]*Stream
	InPackets chan InPacket
}

func NewPacketStreams() PacketStreams {
	s := PacketStreams{}
	s.Streams = map[string]*Stream{}
	s.InPackets = make(chan InPacket, BUF_SIZE)
	return s
}

func (p *PacketStreams) Input(c net.Conn, data []byte) (err error) {
	streamKey := c.RemoteAddr().String()
	stream, ok := p.Streams[streamKey]
	if !ok {
		p.Streams[streamKey] = NewStream(c)
		stream = p.Streams[streamKey]
	}

	err = stream.Input(data)
	if err != nil {
		return
	}
	for {
		packet, err := stream.Unpack()
		if err != nil {
			return err
		}

		p.InPackets <- InPacket{hp:packet, stream:streamKey}
	}
}

func (p *PacketStreams) Output(streamKey string, hp *HopPacket) (err error) {
	stream, ok := p.Streams[streamKey]
	if !ok {
		return errors.New("No this stream!")
	}


	//TODO: sent packets using another go routine
	data := hp.Pack()
	plen := len(data)

	for {

		wlen, err := stream.Connection.Write(data[:plen])
		if err != nil {
			return err
		}
		if wlen == plen {
			return nil
		}

		copy(data[:], data[wlen:])
		plen = plen - wlen
	}
	return
}

func (p *PacketStreams) Close(c net.Conn) {
	key := c.RemoteAddr().String()

	if _, ok := p.Streams[key]; ok {
		delete(p.Streams, key)

	}
}

