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

package protodef

import (
	"github.com/golang/protobuf/proto"
	"testing"
	"reflect"
)

func TestPacketHeader(t *testing.T) {
	test := &TestPacket{
		Mark: false,
		Sid:  999,
		Sessions: map[string]uint64{"a":1, "b":2},

	}
	data, err := proto.Marshal(test)
	if err != nil {
		t.Fatal("marshaling error: ", err)
	}
	newTest := &TestPacket{}
	err = proto.Unmarshal(data, newTest)
	if err != nil {
		t.Fatal("unmarshaling error: ", err)
	}
	// Now test and newTest contain the same data.
	if test.Sid != newTest.Sid {
		t.Fatalf("data mismatch %q != %q", test.Sid, newTest.Sid)
	}
	if test.Mark != newTest.Mark {
		t.Fatalf("data mismatch %q != %q", test.Mark, newTest.Mark)
	}

	if !reflect.DeepEqual(test.Sessions, newTest.Sessions) {
		t.Fatal("Sessions dont mismatch")
	}
}
