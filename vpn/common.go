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
	"github.com/FTwOoO/go-logger"
	"reflect"
	"github.com/FTwOoO/gohop2/protodef"
)

var log *logger.Logger

var allApplicationMessageTypes = []reflect.Type{
	reflect.TypeOf(new(protodef.Ping)),
	reflect.TypeOf(new(protodef.PingAck)),
	reflect.TypeOf(new(protodef.Handshake)),
	reflect.TypeOf(new(protodef.HandshakeAck)),
	reflect.TypeOf(new(protodef.Fin)),
	reflect.TypeOf(new(protodef.FinAck)),
	reflect.TypeOf(new(protodef.Data)),
	reflect.TypeOf(new(protodef.DataAck)),
}

const (
	HOP_STAT_INIT int32 = iota // initing
	HOP_STAT_HANDSHAKE              // handeshaking
	HOP_STAT_WORKING                // working
	HOP_STAT_FIN                    // finishing

)
