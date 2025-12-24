package main

import "C"

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

type Iphdr struct {
	VersionIHL uint8  // 版本(4位) + 头部长度(4位)
	TOS        uint8  // 服务类型
	TotLen     uint16 // 总长度
	ID         uint16 // 标识
	FragOff    uint16 // 分片偏移(13位) + 标志(3位)
	TTL        uint8  // 生存时间
	Protocol   uint8  // 协议类型
	Check      uint16 // 校验和
	SAddr      uint32 // 源地址
	DAddr      uint32 // 目的地址
}

type Tcphdr struct {
	Source uint16 // __be16 source
	Dest   uint16 // __be16 dest
	Seq    uint32 // __be32 seq
	AckSeq uint32 // __be32 ack_seq

	// 对应: __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1
	// 这个字段实际上包含两个部分：
	// 高字节：res1(4位) + doff(4位)
	// 低字节：8个标志位
	Res1DoffFlags uint16 // 完整的16位

	Window uint16 // __be16 window
	Check  uint16 // __sum16 check
	UrgPtr uint16 // __be16 urg_ptr
}

type Event struct {
	Iphdr  Iphdr
	Tcphdr Tcphdr
	Len    uint32
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	prog, err := bpfModule.GetProgram("cgroup__skb_ingress")
	if err != nil {
		common.Error(err)
	}

	cgroupRootDir, err := common.GetCgroupV2RootDir()
	if err != nil {
		common.Error(err)
	}

	// link, err := prog.AttachCgroup(cgroupRootDir)
	link, err := prog.AttachCgroupLegacy(cgroupRootDir, bpf.BPFAttachTypeCgroupInetIngress)
	if err != nil {
		common.Error(err)
	}

	eventsChannel := make(chan []byte, 1)
	lostChannel := make(chan uint64, 1)

	// initialize an eBPF perf buffer to receive events
	bpfPerfBuffer, err := bpfModule.InitPerfBuf(
		"perfbuffer", eventsChannel, lostChannel, 1,
	)
	if err != nil {
		common.Error(err)
	}

	// signal handling
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	// start eBPF perf buffer event polling
	bpfPerfBuffer.Poll(5000)

	testPassed := false

LOOP:
	for {
		select {
		case data := <-eventsChannel:
			var event Event
			err = binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
			if err != nil {
				common.Error(err)
			}
			srcIP := net.IPv4(byte(event.Iphdr.SAddr), byte(event.Iphdr.SAddr>>8),
				byte(event.Iphdr.SAddr>>16), byte(event.Iphdr.SAddr>>24))
			dstIP := net.IPv4(byte(event.Iphdr.DAddr), byte(event.Iphdr.DAddr>>8),
				byte(event.Iphdr.DAddr>>16), byte(event.Iphdr.DAddr>>24))

			srcPort := binary.BigEndian.Uint16([]byte{byte(event.Tcphdr.Source),
				byte(event.Tcphdr.Source >> 8)})
			dstPort := binary.BigEndian.Uint16([]byte{byte(event.Tcphdr.Dest),
				byte(event.Tcphdr.Dest >> 8)})

			fmt.Printf("源IP: %s, 源端口: %d, 目的IP: %s, 目的端口: %d, 数据包长度: %d\n",
				srcIP, srcPort, dstIP, dstPort, event.Len)
			log.Println("Received event, {}", event)
		case <-ctx.Done():
			break LOOP
		}
	}

	err = link.Destroy()
	if err != nil {
		common.Error(err)
	}

	if !testPassed {
		common.Error(errors.New("unable to get all packets"))
	}
}
