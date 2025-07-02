package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jschwinger233/elibpcap"
	"golang.org/x/sync/errgroup"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type cidr_config_val tcFilter ./ebpf/tc_filter.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall -g -O2 -mcpu=v3

const (
	DirectionIngress = 1
	DirectionEgress  = 2

	DirIngress = "INGRESS"
	DirEgress  = "EGRESS"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	flags := parseFlags()
	cfg := newConfig(flags)
	devs := flags.getDevices()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	specTc, err := loadTcFilter()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	eventMapSpec := specTc.Maps["events"]
	eventMap, err := ebpf.NewMap(eventMapSpec)
	if err != nil {
		log.Fatalf("Failed to create perf-event map: %v", err)
	}
	defer eventMap.Close()

	egressCidrConfigMapSpec := specTc.Maps["egress_cidr_config"]
	egressCidrConfigMap, err := ebpf.NewMap(egressCidrConfigMapSpec)
	if err != nil {
		log.Fatalf("Failed to create egress CIDR config hash map: %v", err)
	}
	defer egressCidrConfigMap.Close()
	egressCIDRConfig := egressCIDRConfig{egressCidrConfigMap}
	if err = flags.updateEgresCIDRConfig(egressCIDRConfig); err != nil {
		log.Fatalf("Failed to update egress CIDR config map: %v", err)
	}

	egressDNSConfigMapSpec := specTc.Maps["egress_dns_config"]
	egressDNSConfigMap, err := ebpf.NewMap(egressDNSConfigMapSpec)
	if err != nil {
		log.Fatalf("Failed to create egress DNS config hash map: %v", err)
	}
	defer egressDNSConfigMap.Close()
	egressDNSConfig := egressDNSConfig{egressDNSConfigMap}
	if err = flags.updateEgressDNSConfig(egressDNSConfig); err != nil {
		log.Fatalf("Failed to update egress DNS config map: %v", err)
	}

	progSpec := specTc.Programs["on_ingress"]
	progSpec.Instructions, err = elibpcap.Inject(flags.PcapFilterExpr,
		progSpec.Instructions, elibpcap.Options{
			AtBpf2Bpf:  "filter_pcap_ebpf_l2",
			DirectRead: true,
			L2Skb:      true,
		})
	if err != nil {
		log.Fatalf("Failed to inject pcap filter: %v", err)
	}
	progSpec = specTc.Programs["on_egress"]
	progSpec.Instructions, err = elibpcap.Inject(flags.PcapFilterExpr,
		progSpec.Instructions, elibpcap.Options{
			AtBpf2Bpf:  "filter_pcap_ebpf_l2",
			DirectRead: true,
			L2Skb:      true,
		})
	if err != nil {
		log.Fatalf("Failed to inject pcap filter: %v", err)
	}

	rewriteConst := map[string]interface{}{
		"__cfg": *cfg,
	}

	dnsCache := DNSCache{
		Config: map[string][]net.IP{},
		Notify: make(chan struct{}),
	}
	for _, fqdn := range flags.BlackFQDNList {
		dnsCache.Config[fqdn] = nil
	}

	wg, ctx := errgroup.WithContext(ctx)
	for idx := range devs {
		ifindex, ifname := idx, devs[idx]
		rewriteConst["IFINDEX"] = uint32(ifindex)

		err := newDNSParser(ctx, flags, ifname, dnsCache)
		if err != nil {
			log.Fatalf("Failed to new dns parser for if@%d:%s: %v", ifindex, ifname, err)
		}

		_, okIngress, err := checkTcFilter(ifindex, true)
		if err != nil {
			log.Fatalf("Failed to check tc filter ingress for if@%d:%s: %v", ifindex, ifname, err)
		}

		_, okEgress, err := checkTcFilter(ifindex, false)
		if err != nil {
			log.Fatalf("Failed to check tc filter egress for if@%d:%s: %v", ifindex, ifname, err)
		}

		if !okEgress {
			if err := specTc.RewriteConstants(rewriteConst); err != nil {
				log.Fatalf("Failed to rewrite const for if@%d:%s: %v", ifindex, ifname, err)
			}

			var obj tcFilterObjects
			if err := specTc.LoadAndAssign(&obj, &ebpf.CollectionOptions{
				MapReplacements: map[string]*ebpf.Map{
					"events":             eventMap,
					"egress_cidr_config": egressCidrConfigMap,
					"egress_dns_config":  egressDNSConfigMap,
				},
				Programs: ebpf.ProgramOptions{
					LogSize: ebpf.DefaultVerifierLogSize * 4,
				},
			}); err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					log.Printf("Failed to load bpf obj for if@%d:%s: %v\n%+v", ifindex, ifname, err, ve)
				}
				log.Fatalf("Failed to load bpf obj for if@%d:%s: %v", ifindex, ifname, err)
			}
			defer obj.Close()

			wg.Go(func() error {
				runTcFilter(ctx, &obj, ifindex, ifname, !okIngress, !okEgress, flags.KeepTcQdisc)
				return nil
			})
		}

	}

	// printHashMap(egressCidrConfigMap)

	wg.Go(func() error {
		handlePerfEvent(ctx, eventMap, devs)
		return nil
	})

	wg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-dnsCache.Notify:
				cidrs := make(map[string]*net.IPNet)
				for k, v := range dnsCache.Config {
					for _, ip := range v {
						ipNet := &net.IPNet{
							IP:   ip,
							Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0xff),
						}
						cidrs[ipNet.String()] = ipNet
					}
					log.Printf("dns policy name %s ips %v, len %d cap %d", k, v, len(v), cap(v))
				}

				if err := egressCIDRConfig.Update(cidrs); err != nil {
					log.Fatalf("update egress cidr config map failed: %v", cidrs)
				}
			}
		}
	})

	if err = wg.Wait(); err != nil {
		log.Fatalf("service exit with: %v", err)
	}
}

func runTcFilter(ctx context.Context, obj *tcFilterObjects, ifindex int, ifname string,
	withIngress, withEgress, keepTcQdisc bool,
) {
	if !withIngress && !withEgress {
		return
	}

	if err := replaceTcQdisc(ifindex); err != nil {
		log.Printf("Failed to replace tc-qdisc for if@%d:%s: %v", ifindex, ifname, err)
		return
	} else if !keepTcQdisc {
		defer deleteTcQdisc(ifindex)
	}

	if withIngress {
		if err := addTcFilterIngress(ifindex, obj.OnIngress); err != nil {
			log.Printf("Failed to add tc-filter ingress for if@%d:%s: %v", ifindex, ifname, err)
			return
		} else {
			defer deleteTcFilterIngress(ifindex, obj.OnIngress)
		}

		log.Printf("Listening events for if@%d:%s %s by TC...", ifindex, ifname, DirIngress)
	}

	if withEgress {
		if err := addTcFilterEgress(ifindex, obj.OnEgress); err != nil {
			log.Printf("Failed to add tc-filter egress for if@%d:%s: %v", ifindex, ifname, err)
			return
		} else {
			defer deleteTcFilterEgress(ifindex, obj.OnEgress)
		}

		log.Printf("Listening events for if@%d:%s %s by TC...", ifindex, ifname, DirEgress)
	}

	<-ctx.Done()
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map, devs map[int]string) {
	eventReader, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Printf("Failed to create perf-event reader : %v", err)
		return
	}

	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var ev event
	for {
		event, err := eventReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Printf("Reading perf-event: %v", err)
		}

		if event.LostSamples != 0 {
			log.Printf("Lost %d events", event.LostSamples)
		}

		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)

		ev.output(devs)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func printHashMap(hash *ebpf.Map) {
	var key, value uint32
	hash.Iterate().Next(&key, &value)
	log.Printf("Egress config map dest-addr %v, value %d", key, value)
}
