/*
Copyright (c) 2014 VMware, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package dhcpv4

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test dispatch to ReplyWriter
func TestRequestWriteReply(t *testing.T) {
	rw := &testReplyWriter{}

	msg := Request{
		Packet:      NewPacket(BootRequest),
		ReplyWriter: rw,
	}

	reps := []Reply{
		CreateAck(msg),
		CreateNak(msg),
	}

	for _, rep := range reps {
		rw.wrote = false
		msg.WriteReply(rep)
		assert.True(t, rw.wrote)
	}
}
