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
	"os"
	"syscall"
	"github.com/FTwOoO/vpncore/tcpip"
)

func KillMyself() {
	pid := os.Getpid()
	syscall.Kill(pid, syscall.SIGTERM)
}

func LogIP4Packet(packet []byte, info string) {
	dest := tcpip.IPv4Packet(packet).DestinationIP().To4()
	log.Debugf("%s: ip dest %v",info, dest)
}
