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

package hop

import (
	"time"
	"net"
	"sync/atomic"
	"math/rand"
)

type VPNPeer struct {
	sid          uint32
	ip           net.IP
	seq          uint32
	state        int32
	hsDone       chan struct{}
	lastSeenTime time.Time
	connections  []*net.Conn
}

func NewVPNPeer(id uint32) *VPNPeer {
	hp := new(VPNPeer)
	hp.sid = id
	hp.state = HOP_STAT_INIT
	hp.seq = 0
	hp.lastSeenTime = time.Now()
	hp.connections = new([]*net.Conn)
	hp.hsDone = make(chan struct{})

	return hp
}

func (peer *VPNPeer) AddConnection(conn *net.Conn) {
	append(peer.connections, conn)
}

func (peer *VPNPeer) RandomConn() *net.Conn {
	index := rand.Intn(len(peer.connections))
	return peer.connections[index]
}

func (peer *VPNPeer) NextSeq() uint32 {
	return atomic.AddUint32(&peer.seq, 1)
}

type VPNPeers struct {
	ippool      *IPPool
	peersByIP   map[net.IP]*VPNPeer
	PeersByID   map[uint32]*VPNPeer
	PeerTimeout chan *VPNPeer
}

func NewVPNPeers(subnet *net.IPNet, timeout time.Duration) (vs *VPNPeers) {
	vs = new(VPNPeers)
	vs.ippool = IPPool{subnet:subnet}
	vs.peersByIP = map[net.IP]*VPNPeer{}
	vs.PeerTimeout = new(chan *VPNPeer)

	go vs.checkTimeout(timeout)

	return
}

func (vs *VPNPeers) NewPeer(id uint32) (ip net.IP, err error) {
	ipnet, err := vs.ippool.Next()
	if err != nil {
		return
	}

	peer := NewVPNPeer(id)
	peer.ip = ipnet.IP
	vs.peersByIP[peer.ip] = peer
	vs.PeersByID[id] = peer

	return peer.ip, nil
}

func (vs *VPNPeers) DeletePeer(id uint32) {
	peer, ok := vs.PeersByID[id]
	if !ok {
		return
	}

	vs.ippool.Release(peer.ip)

	delete(vs.PeersByID, id)
	delete(vs.peersByIP, peer.ip)
}

func (vs *VPNPeers) checkTimeout(timeout time.Duration) {
	for sid, peer := range vs.PeersByID {
		log.Debugf("watch: %v", peer.lastSeenTime)
		conntime := time.Since(peer.lastSeenTime)
		if conntime > timeout {
			vs.DeletePeer(sid)
			vs.PeerTimeout <- peer
		}
	}
}