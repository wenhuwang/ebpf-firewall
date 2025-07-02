package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

type flags struct {
	Devices []string

	FilterMark uint32

	KeepTcQdisc bool

	PcapFilterExpr string

	BlackCIDRList []string

	BlackFQDNList []string

	EnableDNSDeny bool

	SnapLen    int
	BufferSize int
}

func parseFlags() *flags {
	var f flags

	flag.StringSliceVarP(&f.Devices, "device", "d", nil, "network devices to run ebpf-firewall")
	flag.Uint32VarP(&f.FilterMark, "filter-mark", "m", 0, "filter mark for ebpf-firewall")

	flag.BoolVarP(&f.KeepTcQdisc, "keep-tc-qdisc", "k", false, "keep tc-qdisc when exit")

	flag.StringSliceVarP(&f.BlackCIDRList, "black-cidr-list", "c", nil, "cidr list to deny, eg: 10.9.25.0/24, 172.16.0.10/32")

	flag.StringSliceVarP(&f.BlackFQDNList, "black-fqdn-list", "f", nil, "fqdn list to deny, eg: www.baidu.com")

	flag.BoolVarP(&f.EnableDNSDeny, "enable-dns-deny", "e", false, "enable dns query deny")

	flag.IntVarP(&f.SnapLen, "snap-len", "s", 0, "Snaplen, if <= 0, use 65535")
	flag.IntVarP(&f.BufferSize, "buffer-size", "b", 8, "Interface buffersize (MB)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [pcap-filter]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    Available pcap-filter: see \"man 7 pcap-filter\"\n")
		fmt.Fprintf(os.Stderr, "    Available options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	f.PcapFilterExpr = strings.Join(flag.Args(), " ")

	return &f
}

func (f *flags) getDevices() map[int]string {
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("Failed to list links: %v", err)
	}

	m := make(map[int]string)
	if len(f.Devices) == 0 {
		for _, l := range links {
			ifindex, ifname := l.Attrs().Index, l.Attrs().Name
			m[ifindex] = ifname
		}

		return m
	}

	target := make(map[string]struct{}, len(f.Devices))
	for _, dev := range f.Devices {
		target[dev] = struct{}{}
	}
	for _, l := range links {
		ifindex, ifname := l.Attrs().Index, l.Attrs().Name
		if _, ok := target[ifname]; ok {
			m[ifindex] = ifname
		}
	}

	return m
}

func (f *flags) updateEgresCIDRConfig(ecc egressCIDRConfig) error {
	if len(f.BlackCIDRList) == 0 {
		return nil
	}

	egressCIDRs := map[string]*net.IPNet{}
	for _, cidr := range f.BlackCIDRList {
		_, net, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		egressCIDRs[net.String()] = net
	}

	return ecc.Update(egressCIDRs)
}

func (f *flags) updateEgressDNSConfig(edc egressDNSConfig) error {
	if !f.EnableDNSDeny || len(f.BlackFQDNList) == 0 {
		return nil
	}

	return edc.Update(f.BlackFQDNList...)
}
