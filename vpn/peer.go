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
	"time"
	"net"
	"sync/atomic"
	"sync"
	"github.com/FTwOoO/vpncore/tcpip"
)

type VPNPeer struct {
	Id            uint32
	Ip            net.IP

	seq           uint32
	State         int32
	HandshakeDone chan struct{}
	LastSeenTime  time.Time
}

func NewVPNPeer(sid uint32, ip net.IP) *VPNPeer {
	hp := new(VPNPeer)
	hp.State = HOP_STAT_INIT
	hp.seq = 0
	hp.Id = sid
	hp.Ip = ip
	hp.LastSeenTime = time.Now()
	hp.HandshakeDone = make(chan struct{})
	return hp
}

func (peer *VPNPeer) NextSeq() uint32 {
	return atomic.AddUint32(&(peer.seq), 1)
}

func (peer *VPNPeer) Touch() {
	peer.LastSeenTime = time.Now()
}

type VPNPeersManager struct {
	MyIp net.IP
	IpPool         *tcpip.IP4Pool
	PeerTimeout    chan *VPNPeer

	peerByIp       map[string]*VPNPeer
	peerById       map[uint32]*VPNPeer
	peerLock       sync.RWMutex

	sessionToPeer  map[uint64]*VPNPeer
	peerToSessions map[*VPNPeer][]uint64
	sessionLock    sync.RWMutex
}

func NewVPNPeers(subnet *net.IPNet, timeout time.Duration) (vs *VPNPeersManager) {
	vs = new(VPNPeersManager)
	vs.IpPool, _ = tcpip.NewIP4Pool(subnet)
	vs.MyIp, _ = vs.IpPool.Next()
	vs.IpPool.Next() // peer ip for server tun interface

	vs.peerByIp = map[string]*VPNPeer{}
	vs.peerById = map[uint32]*VPNPeer{}
	vs.sessionToPeer = map[uint64]*VPNPeer{}
	vs.peerToSessions = map[*VPNPeer][]uint64{}
	vs.PeerTimeout = make(chan *VPNPeer, 100)

	go vs.checkTimeout(timeout)
	return
}

func (vs *VPNPeersManager) checkTimeout(timeout time.Duration) {
	vs.peerLock.RLock()
	defer vs.peerLock.RUnlock()

	for _, peer := range vs.peerByIp {
		log.Debugf("watch: %v", peer.LastSeenTime)
		conntime := time.Since(peer.LastSeenTime)
		if conntime > timeout {
			vs.DeletePeer(peer)
			vs.PeerTimeout <- peer
		}
	}

}

func (vs *VPNPeersManager) NewPeer(id uint32) (peer *VPNPeer, err error) {
	ip, err := vs.IpPool.Next()
	if err != nil {
		return
	}

	peer = NewVPNPeer(id, ip)

	vs.peerLock.Lock()
	vs.peerByIp[peer.Ip.String()] = peer
	vs.peerById[id] = peer
	vs.peerLock.Unlock()

	return
}

func (vs *VPNPeersManager) DeletePeer(peer *VPNPeer) {
	vs.IpPool.Release(peer.Ip)
	delete(vs.peerByIp, peer.Ip.String())
	delete(vs.peerById, peer.Id)

	vs.sessionLock.Lock()
	defer vs.sessionLock.Unlock()
	for _, sid := range vs.peerToSessions[peer] {
		delete(vs.sessionToPeer, sid)
	}
	delete(vs.peerToSessions, peer)
}

func (vs *VPNPeersManager) AddSessionToPeer(peer *VPNPeer, sid uint64) {
	vs.sessionLock.Lock()
	defer vs.sessionLock.Unlock()

	vs.sessionToPeer[sid] = peer
	l, found := vs.peerToSessions[peer]
	if !found {
		vs.peerToSessions[peer] = []uint64{sid}
	} else {

		vs.peerToSessions[peer] = append(l, sid)
	}
}

func (vs *VPNPeersManager) GetPeerByIp(ip net.IP) (*VPNPeer) {
	vs.peerLock.RLock()
	defer vs.peerLock.RUnlock()

	return vs.peerByIp[ip.String()]
}

func (vs *VPNPeersManager) GetPeerById(sid uint32) (*VPNPeer) {
	vs.peerLock.RLock()
	defer vs.peerLock.RUnlock()

	return vs.peerById[sid]
}

func (vs *VPNPeersManager) GetPeerBySession(sid uint64) (*VPNPeer) {
	vs.sessionLock.RLock()
	defer vs.sessionLock.RUnlock()

	return vs.sessionToPeer[sid]
}

func (vs *VPNPeersManager) GetPeerSessions(peer *VPNPeer) ([]uint64) {
	vs.sessionLock.RLock()
	defer vs.sessionLock.RUnlock()
	return vs.peerToSessions[peer]
}

func (vs *VPNPeersManager) GetAllPeers() ([]*VPNPeer) {
	vs.peerLock.RLock()
	defer vs.peerLock.RUnlock()

	peers := []*VPNPeer{}

	for _, peer := range vs.peerById {
		peers = append(peers, peer)
	}
	return peers
}
