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
	Id           uint32
	Ip           net.IP
	seq          uint32
	state        int32
	hsDone       chan struct{}
	LastSeenTime time.Time
	Connections  []*net.Conn
}

func NewVPNPeer(id uint32, ip net.IP) *VPNPeer {
	hp := new(VPNPeer)
	hp.state = HOP_STAT_INIT
	hp.seq = 0
	hp.Id = id
	hp.Ip = ip
	hp.LastSeenTime = time.Now()
	hp.Connections = new([]*net.Conn)
	hp.hsDone = make(chan struct{})

	return hp
}

func (peer *VPNPeer) AddConnection(conn *net.Conn) {
	append(peer.Connections, conn)
}

func (peer *VPNPeer) RandomConn() *net.Conn {
	index := rand.Intn(len(peer.Connections))
	return peer.Connections[index]
}

func (peer *VPNPeer) NextSeq() uint32 {
	return atomic.AddUint32(&peer.seq, 1)
}

type VPNPeers struct {
	ippool      *IPPool
	PeersByIp   map[net.IP]*VPNPeer
	PeerTimeout chan *VPNPeer
	PeersByID   map[uint32]*VPNPeer
}

func NewVPNPeers(subnet *net.IPNet, timeout time.Duration) (vs *VPNPeers) {
	vs = new(VPNPeers)
	vs.ippool = IPPool{subnet:subnet}
	vs.PeersByIp = map[net.IP]*VPNPeer{}
	vs.PeerTimeout = new(chan *VPNPeer)
	go vs.checkTimeout(timeout)
	return
}

func (vs *VPNPeers) NewPeer(id uint32, conn *net.Conn) (peer *VPNPeer, err error) {
	ipnet, err := vs.ippool.Next()
	if err != nil {
		return
	}

	peer = NewVPNPeer(id, ipnet.IP)
	vs.PeersByIp[peer.Ip] = peer
	vs.PeersByID[id] = peer
	vs.AddConnection(conn, peer)
	return
}

func (vs *VPNPeers) AddConnection(conn *net.Conn, peer *VPNPeer) {
	if _, ok := vs.PeersByIp[peer.Ip]; ok {
		peer.AddConnection(conn)
	}
}

func (vs *VPNPeers) DeletePeer(peer *VPNPeer) {
	vs.ippool.Release(peer.Ip)
	delete(vs.PeersByIp, peer.Ip)
	delete(vs.PeersByID, peer.Id)
}

func (vs *VPNPeers) checkTimeout(timeout time.Duration) {
	for _, peer := range vs.PeersByIp {
		log.Debugf("watch: %v", peer.LastSeenTime)
		conntime := time.Since(peer.LastSeenTime)
		if conntime > timeout {
			vs.DeletePeer(peer)
			vs.PeerTimeout <- peer
		}
	}
}