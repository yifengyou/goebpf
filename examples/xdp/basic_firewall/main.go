// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/dropbox/goebpf"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

// 黑名单ip列表
type ipAddressList []string

// Implements flag.Value
// *ipAddressList does not implement flag.Value (missing String method)
// 使用flag.Var库，需要实现对应方法
// func Var(value Value, name string, usage string)
// type Value interface {
//	String() string
//	Set(string) error
//}
func (i *ipAddressList) String() string {
	// “%+v”会以字段键值对的形式key-value格式打印，“%v”只会打印字段值value信息 %#v最详细
	// &{file:0xc00012a780}  %+v
	// &{0xc00012a780} %v
	// &os.File{file:(*os.file)(0xc00012a780)} %#v
	return fmt.Sprintf("%+v", *i)
}

// Implements flag.Value
// *ipAddressList does not implement flag.Value (missing Set method)
func (i *ipAddressList) Set(value string) error {
	// 仅支持16个地址，在elf中map定义了空间是 #define MAX_RULES   16
	if len(*i) == 16 {
		return errors.New("Up to 16 IPv4 addresses supported")
	}
	// Validate that value is correct IPv4 address
	// 限定只能是ipv4地址
	if !strings.Contains(value, "/") {
		value += "/32"
	}
	// 包含':'就不是规范的ipv4地址
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s is not an IPv4 address", value)
	}
	// 无类域间路由（Classless Inter-Domain Routing，CIDR）
	// CIDR表示方法：IP地址/网络ID的位数
	// 如果ip地址能够被正确解析，则表示ip地址ok，否则返回错误
	_, _, err := net.ParseCIDR(value)
	if err != nil {
		// invalid value "10000.10000" for flag -drop: invalid CIDR address: 10000.10000/32
		return err
	}
	// Valid, add to the list
	*i = append(*i, value)
	return nil
}

// 指定网卡
var iface = flag.String("iface", "ens32", "Interface to bind XDP program to")

// 指定ebpf elf程序路径
var elf = flag.String("elf", "ebpf_prog/xdp_fw.elf", "clang/llvm compiled binary file")

// 待屏蔽的ip列表
var ipListToBlock ipAddressList

func main() {
	// 内置flag库，使用指针。可重复
	flag.Var(&ipListToBlock, "drop", "IPv4 CIDR to DROP traffic from, repeatable")
	flag.Parse()
	goebpf.Debug("Enable Debug")
	// 目标网卡
	if *iface == "" {
		fatalError("-iface is required.")
	}
	// 如果待屏蔽的ip列表为空，那没搞头啊，直接报错结束
	if len(ipListToBlock) == 0 {
		fatalError("at least one IPv4 address to DROP required (-drop)")
	}
	// Create eBPF system ; 实例化System对象/描述符
	bpf := goebpf.NewDefaultEbpfSystem()
	// Load .ELF files compiled by clang/llvm
	// 从ELF加载ebpf程序，so，ELF基础知识必须扎实
	// 填充System对象，解析一切可用数据。后续对ebpf的访问都通过bpf句柄
	// 通过系统调用完成map创建
	err := bpf.LoadElf(*elf) // 关键函数
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	// 打印EBPF基本信息
	printBpfInfo(bpf)

	// Get eBPF maps 获取map信息，提前知道有多少个map，挨个安排，获取map句柄
	// 返回map描述符，包括句柄等信息
	fwMap := bpf.GetMapByName("fwMap")
	if fwMap == nil {
		fatalError("eBPF map 'fwMap' not found")
	}
	// 黑名单列表
	blacklistMap := bpf.GetMapByName("blacklistMap")
	if blacklistMap == nil {
		fatalError("eBPF map 'blacklistMap' not found")
	}

	// Get XDP program. Name simply fwMap function from xdp_fw.c:
	//      int firewall(struct xdp_md *ctx) {
	// 通过bpf句柄获取ebpf核心程序句柄
	// 此时程序还未加载到内核，还未真正开始运行
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		fatalError("Program 'firewall' not found.")
	}

	// Populate eBPF map with IPv4 addresses to block
	// 挨个将黑名单安排进去，此时程序仍然没有开始运行，先安排数据
	fmt.Println("Blacklisting IPv4 addresses...")
	for index, ip := range ipListToBlock {
		fmt.Printf("\t%s\n", ip)
		err := blacklistMap.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	fmt.Println()

	// Load XDP program into kernel
	// 加载程序到内核，并没有真正运行
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(*iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
	defer xdp.Detach()

	// 上述是针对内核的行为，下列是用户态行为，监听描述符，周期获取数据

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	// func Notify(c chan<- os.Signal, sig ...os.Signal)
	// Notify函数让signal包将输入信号转发到c。
	// 如果没有列出要传递的信号，会将所有输入信号传递到c；否则只传递列出的输入信号。
	signal.Notify(ctrlC, os.Interrupt)
	// const (
	//	// More invented values for signals
	//	SIGHUP  = Signal(0x1)
	//	SIGINT  = Signal(0x2)
	//	SIGQUIT = Signal(0x3)
	//	SIGILL  = Signal(0x4)
	//	SIGTRAP = Signal(0x5)
	//	SIGABRT = Signal(0x6)
	//	SIGBUS  = Signal(0x7)
	//	SIGFPE  = Signal(0x8)
	//	SIGKILL = Signal(0x9)
	//	SIGSEGV = Signal(0xb)
	//	SIGPIPE = Signal(0xd)
	//	SIGALRM = Signal(0xe)
	//	SIGTERM = Signal(0xf)
	//)

	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println("Press CTRL+C to stop.")
	fmt.Println()

	// 周期执行
	// Print stat every second / exit on CTRL+C
	// func NewTicker(d Duration) *Ticker
	ticker := time.NewTicker(1 * time.Second)

	fmt.Println("IP                 DROPs")

	for {
		select {
		case <-ticker.C:
			for i := 0; i < len(ipListToBlock); i++ {
				value, err := fwMap.LookupInt(i)
				if err != nil {
					fatalError("LookupInt failed: %v", err)
				}
				fmt.Printf("%-18s %-d\n", ipListToBlock[i], value)
			}
		case <-ctrlC:
			// 程序退出会自动清理ebpf运行所需的map、program
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}

// 致命错误输出
func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// 打印ebpf对象的基本信息
func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)
	}
	fmt.Println()
}
