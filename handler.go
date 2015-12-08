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
	"net"

	"golang.org/x/net/ipv4"
)

// PacketReader defines an adaptation of the ReadFrom function (as defined
// net.PacketConn) that includes the interface index the packet arrived on.
type PacketReader interface {
	ReadFrom(b []byte) (n int, addr net.Addr, ifindex int, err error)
}

// PacketWriter defines an adaptation of the WriteTo function (as defined
// net.PacketConn) that includes the interface index the packet should be sent
// on.
type PacketWriter interface {
	WriteTo(b []byte, addr net.Addr, ifindex int) (n int, err error)
}

// PacketConn groups PacketReader and PacketWriter to form a subset of net.PacketConn.
type PacketConn interface {
	PacketReader
	PacketWriter

	Close() error
	LocalAddr() net.Addr
}

type replyWriter struct {
	pw PacketWriter

	// The client address, if any
	addr    net.UDPAddr
	ifindex int
}

func (rw *replyWriter) WriteReply(r Reply) error {
	var err error

	err = r.Validate()
	if err != nil {
		return err
	}

	bytes, err := r.ToBytes()
	if err != nil {
		return err
	}

	msg := r.Message()
	addr := rw.addr
	bcast := msg.GetFlags()[0] & 128

	// Broadcast the reply if the request packet has no address associated with
	// it, or if the client explicitly asks for a broadcast reply.
	if addr.IP.Equal(net.IPv4zero) || bcast > 0 {
		addr.IP = net.IPv4bcast
	}

	_, err = rw.pw.WriteTo(bytes, &addr, rw.ifindex)
	if err != nil {
		return err
	}

	return nil
}

// Handler defines the interface an object needs to implement to handle DHCP
// packets. The handler should do a type switch on the Message object that is
// passed as argument to determine what kind of packet it is dealing with. It
// can use the WriteReply function on the request to send a reply back to the
// peer responsible for sending the request packet. While the handler may be
// blocking, it is not encouraged. Rather, the handler should return as soon as
// possible to avoid blocking the serve loop. If blocking operations need to be
// executed to determine if the request packet needs a reply, and if so, what
// kind of reply, it is recommended to handle this in separate goroutines. The
// WriteReply function can be called from multiple goroutines without needing
// extra synchronization.
type Handler interface {
	ServeDHCP(msg Message)
}

// Serve reads packets off the network and calls the specified handler.
func Serve(pc PacketConn, h Handler) error {
	buf := make([]byte, 65536)

	for {
		n, addr, ifindex, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}

		p, err := PacketFromBytes(buf[:n])
		if err != nil {
			continue
		}

		// Stash interface index in packet structure
		p.ifindex = ifindex

		// Filter everything but requests
		if OpCode(p.Op()[0]) != BootRequest {
			continue
		}

		rw := replyWriter{
			pw: pc,

			addr:    *addr.(*net.UDPAddr),
			ifindex: ifindex,
		}

		var msg Message

		switch p.GetMessageType() {
		case MessageTypeDiscover:
			msg = Discover{p, &rw}
		case MessageTypeRequest:
			msg = Request{p, &rw}
		case MessageTypeDecline:
			msg = Decline{p}
		case MessageTypeRelease:
			msg = Release{p}
		case MessageTypeInform:
			msg = Inform{p, &rw}
		}

		if msg != nil {
			h.ServeDHCP(msg)
		}
	}
}

func ListenAndServe(addr string, h Handler) error {
	if addr == "" {
		addr = ":67"
	}
	l, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	defer l.Close() // Should I not do this?

	c, err := NewPacketConn(l)
	if err != nil {
		return err
	}

	return Serve(c, h)
}

type packetConn struct {
	net.PacketConn
	ipv4pc *ipv4.PacketConn
}

// NewPacketConn returns a PacketConn based on the specified net.PacketConn.
// It adds functionality to return the interface index from calls to ReadFrom
// and include the interface index argument in calls to WriteTo.
func NewPacketConn(pc net.PacketConn) (PacketConn, error) {
	ipv4pc := ipv4.NewPacketConn(pc)
	if err := ipv4pc.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return nil, err
	}

	p := packetConn{
		PacketConn: pc,
		ipv4pc:     ipv4pc,
	}

	return &p, nil
}

// ReadFrom reads a packet from the connection copying the payload into b. It
// returns the network interface index the packet arrived on in addition to the
// default return values of the ReadFrom function.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, int, error) {
	n, cm, src, err := p.ipv4pc.ReadFrom(b)
	if err != nil {
		return n, src, -1, err
	}

	return n, src, cm.IfIndex, err
}

// WriteTo writes a packet with payload b to addr. It explicitly sends the
// packet over the network interface  with the specified index.
func (p *packetConn) WriteTo(b []byte, addr net.Addr, ifindex int) (int, error) {
	cm := &ipv4.ControlMessage{
		IfIndex: ifindex,
	}

	return p.ipv4pc.WriteTo(b, cm, addr)
}
