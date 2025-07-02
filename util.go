package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

func ipToUint(addr net.IP) uint32 {
	addr = addr.To4()
	if addr == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(addr)
}

func uintToIP(addr uint32) string {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, addr)
	return net.IP(buf.Bytes()).To4().String()
}

func maskToUint(mask net.IPMask) uint32 {
	return binary.LittleEndian.Uint32(mask)
}

func toHostBytes32(n uint32) []byte {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, n)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}

func toIP(addr uint32) net.IP {
	return net.IP(toHostBytes32(addr))
}

func toNetMask(addr, mask uint32) *net.IPNet {
	var buf []byte
	buf = append(buf, toHostBytes32(mask)...)
	return &net.IPNet{
		IP:   toIP(addr),
		Mask: net.IPMask(buf),
	}
}

const bytesLength = 128

var (
	ErrInvalidUsage = errors.New("invalid usage")
)

func stringToBytes(input string) ([bytesLength]byte, error) {
	output := [bytesLength]byte{}
	bs := []byte(input)
	if len(bs) > bytesLength {
		return output, fmt.Errorf("%s is longer than %d characters: %w", input, bytesLength, ErrInvalidUsage)
	}
	copy(output[:], bs)
	return output, nil
}
