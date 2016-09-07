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

package conn

import (
	"net"
	"net/url"
	"golang.org/x/net/proxy"
)

type ConnectionDialer struct {
	Url    *url.URL
	dialer proxy.Dialer
}

func (p *ConnectionDialer) Dial(network, addr string) (net.Conn, error) {
	return p.dialer.Dial(network, addr)
}

func FromURL(protoUrl string) (*ConnectionDialer, error) {
	u, err := url.Parse(protoUrl)
	if err != nil {
		return nil, err
	}

	dailer, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, err
	}

	proxy := &ConnectionDialer{
		Url:    u,
		dialer: dailer,
	}

	return proxy, nil
}
