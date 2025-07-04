package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

func withTcnl(fn func(nl *tc.Tc) error) (err error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("failed to open rtnl socket: %w", err)
	}
	defer func() {
		if e := tcnl.Close(); e != nil {
			err = fmt.Errorf("failed to close rtnl socket: %w", err)
		}
	}()

	return fn(tcnl)
}

func htons(n uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}

func prepareTcObjMsgIngress(ifindex int) tc.Msg {
	var msg tc.Msg

	protocol := htons(unix.ETH_P_ALL)

	priority := uint32(1)

	msg.Family = unix.AF_UNSPEC
	msg.Ifindex = uint32(ifindex)
	msg.Parent = core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress)
	msg.Handle = core.BuildHandle(tc.HandleRoot, 1)
	msg.Info = priority<<16 | uint32(protocol)

	return msg
}

func prepareTcObjMsgEgress(ifindex int) tc.Msg {
	var msg tc.Msg

	protocol := htons(unix.ETH_P_ALL)

	priority := uint32(1)

	msg.Family = unix.AF_UNSPEC
	msg.Ifindex = uint32(ifindex)
	msg.Parent = core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress)
	msg.Handle = core.BuildHandle(tc.HandleRoot, 2)
	msg.Info = priority<<16 | uint32(protocol)

	return msg
}

func getTcQdiscObj(ifindex int) *tc.Object {
	msg := prepareTcObjMsgEgress(ifindex)
	msg.Handle = core.BuildHandle(tc.HandleRoot, 0)
	msg.Parent = tc.HandleIngress

	return &tc.Object{
		Msg: msg,
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
}

func replaceTcQdisc(ifindex int) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Qdisc().Replace(getTcQdiscObj(ifindex))
	})
}

func deleteTcQdisc(ifindex int) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Qdisc().Delete(getTcQdiscObj(ifindex))
	})
}

func getTcFilterIngressObj(ifindex int, prog *ebpf.Program) *tc.Object {
	var obj tc.Object

	progFD := uint32(prog.FD())
	annotation := "tcfilter.o:[on_ingress]"

	obj.Msg = prepareTcObjMsgIngress(ifindex)
	obj.Attribute.Kind = "bpf"
	obj.Attribute.BPF = new(tc.Bpf)
	obj.Attribute.BPF.FD = &progFD
	obj.Attribute.BPF.Name = &annotation

	return &obj
}

func addTcFilterIngress(ifindex int, prog *ebpf.Program) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Filter().Add(getTcFilterIngressObj(ifindex, prog))
	})
}

func deleteTcFilterIngress(ifindex int, prog *ebpf.Program) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Filter().Delete(getTcFilterIngressObj(ifindex, prog))
	})
}

func getTcFilterEgressObj(ifindex int, prog *ebpf.Program) *tc.Object {
	var obj tc.Object

	progFD := uint32(prog.FD())
	annotation := "tcfilter.o:[on_egress]"
	flags := uint32(0x1)

	obj.Msg = prepareTcObjMsgEgress(ifindex)
	obj.Attribute.Kind = "bpf"
	obj.Attribute.BPF = new(tc.Bpf)
	obj.Attribute.BPF.FD = &progFD
	obj.Attribute.BPF.Name = &annotation
	obj.Attribute.BPF.Flags = &flags

	return &obj
}

func addTcFilterEgress(ifindex int, prog *ebpf.Program) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Filter().Add(getTcFilterEgressObj(ifindex, prog))
	})
}

func deleteTcFilterEgress(ifindex int, prog *ebpf.Program) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Filter().Delete(getTcFilterEgressObj(ifindex, prog))
	})
}

func checkTcFilter(ifindex int, isIngress bool) (*ebpf.Program, bool, error) {
	var prog *ebpf.Program

	err := withTcnl(func(nl *tc.Tc) error {
		var msg tc.Msg
		if isIngress {
			msg = prepareTcObjMsgIngress(ifindex)
		} else {
			msg = prepareTcObjMsgEgress(ifindex)
		}
		log.Printf("tc msg %v, isIngress %t", msg, isIngress)
		attrs, err := nl.Filter().Get(&msg)
		if err != nil {
			return fmt.Errorf("failed to get tc filter: %w", err)
		}

		if len(attrs) == 0 {
			log.Printf("ifindex %d attrs length is 0", ifindex)
			return nil
		}

		for i := range attrs {
			attr := attrs[i].Attribute
			if attr.BPF == nil {
				continue
			}

			progFD, progID := attr.BPF.FD, attr.BPF.ID
			if progID != nil {
				prog, err = ebpf.NewProgramFromID(ebpf.ProgramID(*progID))
				if err != nil {
					return fmt.Errorf("failed to get ingress filter bpf prog: %w", err)
				}
				return nil
			}
			if progFD == nil {
				prog, err = ebpf.NewProgramFromFD(int(*progFD))
				if err != nil {
					return fmt.Errorf("failed to get ingress filter bpf prog: %w", err)
				}
				return nil
			}
		}

		return nil
	})
	if err != nil {
		return nil, false, err
	}

	return prog, prog != nil, nil
}
