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

import "net"

type RawPacket struct {
	conn net.Conn
	data []byte
}

func (p *RawPacket) Send() error {
	num := len(p.data)

	for {
		if num <= 0 {
			break
		}

		n, err := p.conn.Write(p.data)
		if err != nil {
			return err
		}

		num -= n
	}

	return nil
}

