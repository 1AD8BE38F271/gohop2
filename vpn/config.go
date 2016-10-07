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
	"github.com/naoina/toml"
	"os"
	"io/ioutil"
	"github.com/FTwOoO/go-logger"
	"github.com/FTwOoO/vpncore/conn"
	"time"
)

var log logger.Logger

// Server Config
type VPNConfig struct {
	Protocol    conn.TransProtocol `toml:"protocol"`
	Cipher      string `toml:"cipher"`
	Password    string `toml:"password"`
	ServerAddr  string `toml:"server-addr"`
	DNS         string `toml:"local-dns"`
	ListenAddr  string `toml:"addr"`
	PortStart   int    `toml:"port-start"`
	PortEnd     int    `toml:"port-end"`
	Subnet      string `toml:"subnet"`
	MTU         int    `toml:"mtu"`
	Key         string `toml:"key"`
	PeerTimeout time.Duration    `toml:"peertimeout"`
	LogFile     string `toml:"logfile"`
	LogLevel    logger.LogLevel `toml:"loglevel"`
}

func NewVPNConfig(path string) (c *VPNConfig, err error) {

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}
	var config VPNConfig
	if err = toml.Unmarshal(buf, &config); err != nil {
		return
	}

	return &config, nil
}