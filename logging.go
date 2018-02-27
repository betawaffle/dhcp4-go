package dhcp4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/coreos/pkg/capnslog"
)

var clog = capnslog.NewPackageLogger("github.com/betawaffle/dhcp4-go", "dhcp")

var optionFormats = map[Option]func([]byte) string{
	OptionDHCPMsgType:    nil,
	OptionDHCPMaxMsgSize: nil, // func(b []byte) string { return fmt.Sprintf("max_msg_size=%d", binary.BigEndian.Uint16(b)) },
	OptionParameterList:  nil, // func(b []byte) string { return "param_list=..." }
	OptionClientID:       func(b []byte) string { return "client_id=" + formatHex(b) },
	OptionClientNDI:      func(b []byte) string { return "client_ndi=" + formatNDI(b) },
	OptionDHCPServerID:   func(b []byte) string { return "dhcp_server=" + net.IP(b).String() },
	OptionDomainServer:   func(b []byte) string { return "dns=" + formatIP(b) },
	OptionHostname:       func(b []byte) string { return "hostname=" + string(b) },
	OptionAddressRequest: func(b []byte) string { return "requested_ip=" + net.IP(b).String() },
	OptionAddressTime:    func(b []byte) string { return "lease_time=" + formatSeconds(b) },
	OptionSubnetMask:     func(b []byte) string { return "netmask=" + net.IP(b).String() },
	OptionRouter:         func(b []byte) string { return "routers=" + formatIP(b) },
	OptionLogServer:      func(b []byte) string { return "syslog=" + formatIP(b) },
	OptionUUIDGUID:       func(b []byte) string { return "uuid=" + formatUUID(b[1:]) },
	OptionVendorSpecific: func(b []byte) string { return "vendor_specific=" + formatHex(b) },
	OptionClassID:        func(b []byte) string { return fmt.Sprintf("class_id=%q", b) },
	OptionClientSystem:   func(b []byte) string { return fmt.Sprintf("client_arch=%d", binary.BigEndian.Uint16(b)) },
	OptionDHCPMessage:    func(b []byte) string { return fmt.Sprintf("msg=%q", b) },
	OptionUserClass:      func(b []byte) string { return fmt.Sprintf("user_class=%q", b) },
}

func SetOptionFormatter(o Option, fn func([]byte) string) {
	optionFormats[o] = fn
}

func formatHex(b []byte) string {
	const hex = "0123456789abcdef"

	buf := append(make([]byte, 0, len(b)*2+len(b)+2), '"')
	for i, c := range b {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hex[c>>4], hex[c&0xF])
	}
	buf = append(buf, '"')
	return string(buf)
}

func formatIP(b []byte) string {
	if len(b)%4 != 0 {
		return fmt.Sprintf("%q", b)
	}
	ips := make([]string, 0, len(b)/4)
	for i := 0; i < len(b); i += 4 {
		ips = append(ips, net.IP(b[i:i+4]).String())
	}
	return strings.Join(ips, ",")
}

func formatNDI(b []byte) string {
	if len(b) != 3 {
		return formatHex(b)
	}
	if t := b[0]; t == 1 {
		return fmt.Sprintf("UNDI-%d.%d", b[1], b[2])
	}
	return fmt.Sprintf("%d-%d.%d", b[0], b[1], b[2])
}

func formatSeconds(b []byte) string {
	var (
		secs = binary.BigEndian.Uint32(b)
		dur  = time.Duration(secs) * time.Second
	)
	return dur.String()
}

func formatUUID(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type serverRecv struct {
	msg     *Packet
	ip      net.IP
	ifindex int
}

func (sr *serverRecv) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("event=recv")

	buf.WriteString(` mac="`)
	buf.WriteString(sr.msg.GetCHAddr().String())
	buf.WriteString(`"`)

	if sr.msg.GetGIAddr().Equal(sr.ip) {
		buf.WriteString(" via=")
	} else {
		buf.WriteString(" src=")
	}
	buf.WriteString(sr.ip.String())

	if iface, err := net.InterfaceByIndex(sr.ifindex); err == nil {
		buf.WriteString(" iface=")
		buf.WriteString(iface.Name)
	}

	writePacketInfo(buf, sr.msg)

	return buf.String()
}

type serverSend struct {
	req     *Packet
	rep     *Packet
	ip      net.IP
	ifindex int
}

func (ss *serverSend) String() string {
	buf := new(bytes.Buffer)

	buf.WriteString("event=send")

	buf.WriteString(` mac="`)
	buf.WriteString(ss.req.GetCHAddr().String())
	buf.WriteString(`"`)

	if ss.req.GetGIAddr().Equal(ss.ip) {
		buf.WriteString(" via=")
	} else {
		buf.WriteString(" dst=")
	}
	buf.WriteString(ss.ip.String())

	if iface, err := net.InterfaceByIndex(ss.ifindex); err == nil {
		buf.WriteString(" iface=")
		buf.WriteString(iface.Name)
	}

	writePacketInfo(buf, ss.rep)

	return buf.String()
}

func writePacketInfo(buf *bytes.Buffer, p *Packet) {
	buf.WriteString(" xid=")
	buf.WriteString(formatHex(p.XID()))

	buf.WriteString(" type=")
	buf.WriteString(p.GetMessageType().String())

	if addr := p.GetYIAddr(); !net.IPv4zero.Equal(addr) {
		buf.WriteString(" address=")
		buf.WriteString(addr.String())
	}

	if secs := binary.BigEndian.Uint16(p.Secs()); secs > 0 {
		fmt.Fprintf(buf, " secs=%d", secs)
	}

	if addr := p.GetSIAddr(); !net.IPv4zero.Equal(addr) {
		buf.WriteString(" next_server=")
		buf.WriteString(addr.String())
	}

	if filename := nulTerminated(p.File()); len(filename) > 0 {
		buf.WriteString(" filename=")
		buf.Write(filename)
	}

	writeOptions(buf, p.OptionMap)
}

func nulTerminated(b []byte) []byte {
	if i := bytes.IndexByte(b, 0); i != -1 {
		return b[:i]
	}
	return b
}

func writeOptions(buf *bytes.Buffer, om OptionMap) {
	for _, o := range om.GetSortedOptions() {
		fn, ok := optionFormats[o]
		if !ok {
			fmt.Fprintf(buf, " option(%d)=%q", o, om[o])
			continue
		}
		if fn == nil {
			continue
		}
		if s := fn(om[o]); s != "" {
			buf.WriteByte(' ')
			buf.WriteString(s)
		}
	}
}
