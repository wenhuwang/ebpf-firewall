# ebpf-firewall


## Usage

```bash
# ./ebpf-firewall -h
Usage: ./ebpf-firewall [options] [pcap-filter]
    Available pcap-filter: see "man 7 pcap-filter"
    Available options:
  -d, --device strings       network devices to run ebpf-firewall
  -m, --filter-mark uint32   filter mark for ebpf-firewall
  -k, --keep-tc-qdisc        keep tc-qdisc when exit
pflag: help requested
```

An output example:

```bash
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 144, id 0x93f6, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116972675, ack 64800706, flags PSH,ACK, win 165
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 88, id 0x93f7, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116972767, ack 64800706, flags PSH,ACK, win 165
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 128, id 0x93f8, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116972803, ack 64800706, flags PSH,ACK, win 165
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 344, id 0x93f9, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116972879, ack 64800706, flags PSH,ACK, win 165
ifindex: 2(enp1s0) dir=egress mark=0x0(0)
        ETH: 56:00:03:e1:40:a6 -> fe:00:03:e1:40:a6, protocol IPv4
        IPv4: 149.28.xx.yy -> 118.200.xxx.yy, header length 20, dscp 0x10, total length 384, id 0x93fa, TTL 64, protocol TCP
        TCP: 22 -> 57680, seq 1116973171, ack 64800706, flags PSH,ACK, win 165
```

## Requirements

`ebpf-firewall` requires >= 5.2 kernel to run.

## Build

With latest `libpcap` installed, build `ebpf-firewall` with:

```bash
go generate
CGO_ENABLED=1 go build
# ignore cgo warnings
```

Install latest `libpcap` on Ubuntu:

```bash
# Get latest libpcap from https://www.tcpdump.org/
wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz
cd libpcap-1.10.4
./configure --disable-rdma --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl
make
sudo make install
```