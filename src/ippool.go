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
	"errors"
	"net"
	"sync/atomic"
)

//实现可以放到Interface中实现
type IPPool struct {
	subnet *net.IPNet
	pool   [256]int32
}

var poolFull = errors.New("IP Pool Full")

func (p *IPPool) Next() (*net.IPNet, error) {
	found := false
	var i int
	for i = 3; i < 255; i += 2 {
		if atomic.CompareAndSwapInt32(&p.pool[i], 0, 1) {
			found = true
			break
		}
	}
	if !found {
		return nil, poolFull
	}

	ipnet := &net.IPNet{
		make([]byte, 4),
		make([]byte, 4),
	}
	copy([]byte(ipnet.IP), []byte(p.subnet.IP))
	copy([]byte(ipnet.Mask), []byte(p.subnet.Mask))
	ipnet.IP[3] = byte(i)
	return ipnet, nil
}

func (p *IPPool) Release(ip net.IP) {
	defer func() {
		if err := recover(); err != nil {
			//logger.Errorf("%v", err)
		}
	}()

	//logger.Debugf("releasing ip: %v", ip)
	i := ip[3]
	p.pool[i] = 0
}
