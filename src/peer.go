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
	"sync"
	math_rand "math/rand"
)

// gohop Peer is a record of a peer's available UDP addrs
type VPNPeer struct {
	id           uint64
	ip           net.IP
	addrs        map[[6]byte]int //UDP地址到channel
	_addrs_lst   []*hUDPAddr     // i know it's ugly!
	seq          uint32
	state        int32
	hsDone       chan struct{}   // Handshake done
	recvBuffer   *hopPacketBuffer
	srv          *CandyVPNServer
	_lock        sync.RWMutex
	lastSeenTime time.Time
}

func newHopPeer(id uint64, srv *CandyVPNServer, addr *net.UDPAddr, idx int) *VPNPeer {
	hp := new(VPNPeer)
	hp.id = id
	hp._addrs_lst = make([]*hUDPAddr, 0)
	hp.addrs = make(map[[6]byte]int)
	hp.state = HOP_STAT_INIT
	hp.seq = 0
	hp.srv = srv
	hp.recvBuffer = newHopPacketBuffer(srv.toIface)

	a := newhUDPAddr(addr)
	hp._addrs_lst = append(hp._addrs_lst, a)
	hp.addrs[a.hash] = idx

	return hp
}

func (h *VPNPeer) Seq() uint32 {
	return atomic.AddUint32(&h.seq, 1)
}

func (h *VPNPeer) addr() (*net.UDPAddr, int, bool) {
	defer h._lock.RUnlock()
	h._lock.RLock()

	random_index := math_rand.Intn(len(h._addrs_lst))
	addr := h._addrs_lst[random_index]
	idx, ok := h.addrs[addr.hash]

	return addr.u, idx, ok
}

func (h *VPNPeer) insertAddr(addr *net.UDPAddr, idx int) {
	defer h._lock.Unlock()
	h._lock.Lock()
	a := newhUDPAddr(addr)
	if _, found := h.addrs[a.hash]; !found {
		h.addrs[a.hash] = idx
		h._addrs_lst = append(h._addrs_lst, a)
	}
}

