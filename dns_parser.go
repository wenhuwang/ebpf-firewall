package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

type afpacketHandle struct {
	TPacket *afpacket.TPacket
}

func newAfpacketHandle(device string, snaplen int, block_size int, num_blocks int,
	timeout time.Duration) (*afpacketHandle, error) {

	h := &afpacketHandle{}
	var err error

	if device == "any" {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(block_size),
			afpacket.OptNumBlocks(num_blocks),
			afpacket.OptAddVLANHeader(false),
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	} else {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptInterface(device),
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(block_size),
			afpacket.OptNumBlocks(num_blocks),
			afpacket.OptAddVLANHeader(false),
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	}
	return h, err
}

// ZeroCopyReadPacketData satisfies ZeroCopyPacketDataSource interface
func (h *afpacketHandle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return h.TPacket.ZeroCopyReadPacketData()
}

// SetBPFFilter translates a BPF filter string into BPF RawInstruction and applies them.
func (h *afpacketHandle) SetBPFFilter(filter string, snaplen int) (err error) {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	if err != nil {
		return err
	}
	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}
	if h.TPacket.SetBPF(bpfIns); err != nil {
		return err
	}
	return h.TPacket.SetBPF(bpfIns)
}

// LinkType returns ethernet link type.
func (h *afpacketHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// Close will close afpacket source.
func (h *afpacketHandle) Close() {
	h.TPacket.Close()
}

// SocketStats prints received, dropped, queue-freeze packet stats.
func (h *afpacketHandle) SocketStats() (as afpacket.SocketStats, asv afpacket.SocketStatsV3, err error) {
	return h.TPacket.SocketStats()
}

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("Interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

// Packet represents a sniffed packet
type Packet struct {
	Proto string

	SrcIP   net.IP
	SrcPort uint16

	DstIP   net.IP
	DstPort uint16

	DNS layers.DNS
}

var (
	arp     layers.ARP
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	dns     layers.DNS
	payload gopacket.Payload
)

var ebpfFilter = "src port 53"

func parse(packetData []byte) (*Packet, error) {
	pkt := &Packet{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &udp, &tcp, &dns, &payload)
	decoded := []gopacket.LayerType{}

	err := parser.DecodeLayers(packetData, &decoded)
	if err != nil {
		return nil, err
	}

	for _, layerType := range decoded {
		switch layerType {
		// case layers.LayerTypeIPv4:
		// 	pkt.SrcIP = ip4.SrcIP
		// 	pkt.DstIP = ip4.DstIP
		// case layers.LayerTypeIPv6:
		// 	pkt.SrcIP = ip6.SrcIP
		// 	pkt.DstIP = ip6.DstIP
		case layers.LayerTypeTCP:
			pkt.Proto = "tcp"
			pkt.SrcPort = uint16(tcp.SrcPort)
			pkt.DstPort = uint16(tcp.DstPort)
		case layers.LayerTypeUDP:
			pkt.Proto = "udp"
			pkt.SrcPort = uint16(udp.SrcPort)
			pkt.DstPort = uint16(udp.DstPort)
		case layers.LayerTypeDNS:
			pkt.Proto = "dns"
			if pkt.SrcPort == 53 {
				pkt.DNS.Questions = dns.Questions
				pkt.DNS.OpCode = dns.OpCode
				pkt.DNS.Answers = dns.Answers
			}
		}
	}

	if pkt.SrcPort != 53 {
		return nil, nil
	}
	return pkt, nil
}

type DNSCache struct {
	Config map[string][]net.IP
	Notify chan struct{}
}

func newDNSParser(ctx context.Context, flags *flags, ifname string, dnsCache DNSCache) error {
	log.Printf("Starting dns parser on interface %q", ifname)

	if flags.SnapLen <= 0 {
		flags.SnapLen = 65535
	}
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(flags.BufferSize, flags.SnapLen, os.Getpagesize())
	if err != nil {
		return errors.Join(errors.New("failed to compute packet size"), err)
	}
	afpacketHandle, err := newAfpacketHandle(ifname, szFrame, szBlock, numBlocks, pcap.BlockForever)
	if err != nil {
		return errors.Join(errors.New("failed to new AfpacketHandle"), err)
	}
	err = afpacketHandle.SetBPFFilter(ebpfFilter, flags.SnapLen)
	if err != nil {
		return errors.Join(errors.New("failed to set BPF filter"), err)
	}

	go func() {
		source := gopacket.ZeroCopyPacketDataSource(afpacketHandle)
		defer afpacketHandle.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				data, _, err := source.ZeroCopyReadPacketData()
				if err != nil {
					log.Fatal(err)
				}
				pkt, err := parse(data)
				if err != nil {
					continue
				}

				if pkt != nil && pkt.DNS.OpCode == 0 && len(pkt.DNS.Questions) == 1 {
					query := pkt.DNS.Questions[0]
					fqdn := query.Name
					qtype := query.Type
					if _, ok := dnsCache.Config[string(fqdn)]; ok && qtype == layers.DNSTypeA {
						dnsCache.Config[string(fqdn)] = dnsCache.Config[string(fqdn)][:0]
						for _, as := range pkt.DNS.Answers {
							if len(as.IP) == net.IPv4len {
								dnsCache.Config[string(fqdn)] = append(dnsCache.Config[string(fqdn)], copyIP(as.IP))
								// log.Printf("host %s values is %v", string(fqdn), dnsCache.Config[string(fqdn)])
							}
						}
						dnsCache.Notify <- struct{}{}
					}
				}
			}
		}
	}()

	return nil
}

func copyIP(x net.IP) net.IP {
	y := make(net.IP, len(x))
	copy(y, x)
	return y
}
