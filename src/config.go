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
	"github.com/naoina/toml"
	"os"
	"io/ioutil"
)


// Server Config
type CandyVPNServerConfig struct {
	ListenAddr  string
	HopStart    int
	HopEnd      int
	Subnet      string
	MTU         int
	Key         string
	PeerTimeout int
	Up          string
	Down        string
}

func NewCandyVPNServerConfig(path string) (c *CandyVPNServerConfig, err error) {

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}
	var config CandyVPNServerConfig
	if err = toml.Unmarshal(buf, &config); err != nil {
		return
	}

	return &config, nil
}