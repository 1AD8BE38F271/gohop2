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
	Len        uint32
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
	s.Len += uint32(len(data))
	return nil
}

func (s *Stream) Unpack() (p *HopPacket, err error) {
	p, remainBytes, err := s.tryUnpackHopPacket()
	if err != nil && err != needMoreData {
		return
	}

	if remainBytes > 0 {
		copy(s.InBuf[:], s.InBuf[s.Len - remainBytes:])
		s.Len = remainBytes
	} else {
		s.Len = 0
	}

	return nil, needMoreData
}

func (s *Stream) tryUnpackHopPacket() (p *HopPacket, remainBytes uint32, err error) {
	if s.Len < 16 {
		return nil, 0, needMoreData
	}

	buf := bytes.NewBuffer(s.InBuf[:s.Len])
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

	if s.Len < 16 + p.Dlen {
		return nil, 0, needMoreData
	}

	var datapacket AppPacket
	if p.Proto == HOP_FLG_HSH {
		datapacket = new(HandshakePacket)
	}else if p.Proto == HOP_FLG_FIN {
		datapacket = new(FinPacket)
	} else if p.Proto == HOP_FLG_PING {
		datapacket = new(PingPacket)
	} else if p.Proto == HOP_FLG_DAT {
		datapacket = new(DataPacket)
	} else if p.Proto == HOP_FLG_HSH_ACK {
		datapacket = new(HandshakeAckPacket)
	} else if p.Proto == HOP_FLG_HSH_ERR {

	} else if p.Proto == HOP_FLG_FIN_ACK {
		datapacket = new(FinAckPacket)
	} else if p.Proto == HOP_FLG_DAT_ACK {
	} else {
		return nil, 0, errors.New("Error Proto flag!")
	}

	if err = datapacket.Unpack(buf); err != nil {
		return
	}

	remainBytes = (uint32)(buf.Len())
	return p, remainBytes, nil
}

func (s *Stream) Close() error {
	return s.Connection.Close()
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

func (p *PacketStreams) AddConnection(c net.Conn) (streamKey string, err error) {
	streamKey = c.RemoteAddr().String()
	if oldstream, ok := p.Streams[streamKey]; ok {
		oldstream.Close()
	}

	p.Streams[streamKey] = NewStream(c)
	return
}

func (p *PacketStreams) Read(streamKey string) (err error) {
	stream, ok := p.Streams[streamKey]
	if !ok {
		return fmt.Errorf("Stream with key %s not found!", streamKey)
	}

	buf := make([]byte, IFACE_BUFSIZE)

	n, err := stream.Connection.Read(buf)
	if err != nil {
		return
	}
	log.Debugf("New incomming packet, len: %d", n)
	err = p.Input(streamKey, buf[:n])
	return
}

func (p *PacketStreams) Input(streamKey string, data []byte) (err error) {
	stream, ok := p.Streams[streamKey]
	if !ok {
		return fmt.Errorf("Stream with key %s not found!", streamKey)
	}

	err = stream.Input(data)
	if err != nil {
		return
	}
	for {
		packet, err := stream.Unpack()
		if err == needMoreData {
			return nil
		}

		if err != nil {
			return err
		}

		p.InPackets <- InPacket{hp:packet, stream:streamKey}
	}
}

func (p *PacketStreams) Write(streamKey string, hp *HopPacket) (err error) {
	stream, ok := p.Streams[streamKey]
	if streamKey == "" || !ok {
		return errors.New("No this stream!")
	}


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

func (p *PacketStreams) Close(streamKey string) error {
	stream, ok := p.Streams[streamKey]
	if !ok {
		return errors.New("No this stream!")
	} else {
		delete(p.Streams, streamKey)
		stream.Close()
		return nil
	}
}

