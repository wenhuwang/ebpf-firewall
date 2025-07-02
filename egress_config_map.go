package main

import (
	"bytes"
	"fmt"
	"net"
	"sort"

	"github.com/cilium/ebpf"
)

type CidrConfigVal tcFilterCidrConfigVal

type egressCIDRConfig struct {
	*ebpf.Map
}

func (e *egressCIDRConfig) Update(cidrMap map[string]*net.IPNet) error {
	// idx=0 holds the number of cidrs
	numCIDRs := len(cidrMap)
	err := e.Put(uint32(0), uint64(numCIDRs))
	if err != nil {
		return fmt.Errorf("unable to store cidr length len=%d", numCIDRs)
	}

	// allow CIDRs
	// index 1..256
	for i, cidr := range orderedCIDRMap(cidrMap) {
		idx := i + 1
		err = e.Put(uint32(idx), cidr)
		if err != nil {
			return fmt.Errorf("unable to put cidr cidr=%s: %s", toNetMask(cidr.Addr, cidr.Mask), err)
		}
	}
	return nil
}

func orderedCIDRMap(cidr map[string]*net.IPNet) []CidrConfigVal {
	keys := []string{}
	for k := range cidr {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := []CidrConfigVal{}
	for _, key := range keys {
		val := cidr[key]
		if val.IP.IsUnspecified() || bytes.Equal(val.Mask, []byte{0, 0, 0, 0}) {
			continue
		}
		bpfVal := CidrConfigVal{
			Addr: ipToUint(val.IP),
			Mask: maskToUint(val.Mask),
		}
		out = append(out, bpfVal)
	}
	return out
}

type egressDNSConfig struct {
	*ebpf.Map
}

func (e *egressDNSConfig) Update(fqdnList ...string) error {
	for _, fqdn := range fqdnList {
		key, err := stringToBytes(fqdn)
		if err != nil {
			return err
		}
		if err := e.Put(key, uint64(0)); err != nil {
			return fmt.Errorf("unable to put DNS config fqdn=%s: %s", fqdn, err)
		}
	}
	return nil
}
