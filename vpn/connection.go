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
	"github.com/FTwOoO/link"
	"github.com/FTwOoO/vpncore/conn"
	"github.com/FTwOoO/vpncore/enc"
	"github.com/FTwOoO/vpncore/conn/stream"
	"net"
	"github.com/FTwOoO/vpncore/conn/crypt"
)

func CreateServer(tranProtocol conn.TransProtocol, address string,  cipher enc.Cipher, password string, codecProtocol link.Protocol) (*link.Server, error) {
	context1 := &stream.StreamLayerContext{
		Protocol:tranProtocol,
		ListenAddr:address,
		RemoveAddr:""}
	context2 := &crypt.CryptLayerContext{BlockConfig:&enc.BlockConfig{Cipher:cipher, Password:password}}

	listener, err := conn.NewListener([]conn.ConnLayerContext{context1, context2})
	if err != nil {
		return nil, err
	}

	return link.NewServer(listener, codecProtocol, 0x100), nil
}

func CreateClient(tranProtocol conn.TransProtocol, address string, cipher enc.Cipher, password string, codecProtocol link.Protocol) (*link.Client, error) {
	context1 := &stream.StreamLayerContext{
		Protocol:tranProtocol,
		ListenAddr:"",
		RemoveAddr:address}
	context2 := &crypt.CryptLayerContext{BlockConfig:&enc.BlockConfig{Cipher:cipher, Password:password}}

	dialer := link.DialerFunc(func() (net.Conn, error) {
		log.Debugf("Dial to %s with transProtocol[%s] cipher[%s] password[%s]",
		address, tranProtocol, cipher, password)
		return conn.Dial([]conn.ConnLayerContext{context1, context2})
	})

	client := link.NewClient(dialer, codecProtocol, 0, 0, 0)
	return client, nil
}