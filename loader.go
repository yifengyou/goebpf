// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// MapSectionName is name of ELF section for maps maps所在节名称
	MapSectionName = "maps"
	// LicenseSectionName is name of ELF section for license info 协议名称所在节
	LicenseSectionName = "license"

	// Length of BPF instruction bpf指令长度，当前固定为8字节
	bpfInstructionLen = 8
	// Other BPF constants that are not present in "golang.org/x/sys/unix"
	bpfDw          = 0x18 // ld/ldx double word
	bpfPseudoMapFd = 1    // pseudo map fd (to be replaced with actual fd)
)

// Supported ELF section names and function how to create program of it type
type programCreator func(bp BaseProgram) Program

var sectionNameToProgramType = map[string]programCreator{
	"xdp":           newXdpProgram,
	"socket_filter": newSocketFilterProgram,
	"kprobe":        newKprobeProgram,
	"kretprobe":     newKretprobeProgram,
	"tc_cls":        newTcSchedClsProgram,
	"tc_act":        newTcSchedActProgram,
}

// BPF instruction //
// Must be in sync with linux/bpf.h: 必须保持一致
// 	struct bpf_insn {
// 		__u8	code;		/* opcode 操作码 8bit */
// 		__u8	dst_reg:4;	/* dest register 目标操作数寄存器 4bit */
// 		__u8	src_reg:4;	/* source register 源操作数寄存器 4bit */
// 		__s16	off;		/* signed offset 有符号偏移量 16bit */
// 		__s32	imm;		/* signed immediate constant 有符号立即数常量 32bit */
// 	};
type bpfInstruction struct {
	code   uint8  // Opcode
	dstReg uint8  // 4 bits: destination register, r0-r10 只使用4比特
	srcReg uint8  // 4 bits: source register, r0-r10 只使用4比特
	offset uint16 // Signed offset
	imm    uint32 // Immediate constant
}

// Loads BPF instruction from binary slice
func (b *bpfInstruction) load(data []byte) error {
	if len(data) < bpfInstructionLen {
		return errors.New("Invalid BPF bytecode")
	}

	b.code = data[0]
	b.dstReg = data[1] & 0xf
	b.srcReg = data[1] >> 4
	b.offset = binary.LittleEndian.Uint16(data[2:])
	b.imm = binary.LittleEndian.Uint32(data[4:])

	return nil
}

// Converts BPF instruction into bytes
func (b *bpfInstruction) save() []byte {
	res := make([]byte, bpfInstructionLen)
	res[0] = b.code
	res[1] = (b.srcReg << 4) | (b.dstReg & 0x0f)
	binary.LittleEndian.PutUint16(res[2:], b.offset)
	binary.LittleEndian.PutUint32(res[4:], b.imm)

	return res
}

// Helper to read/parse all relocations from given section
type relocationItem struct {
	offset int
	symbol elf.Symbol
}

func readRelocations(elfFile *elf.File, section *elf.Section) ([]relocationItem, error) {
	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("symbols() failed: %v", err)
	}
	// Read section data
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("unable to read data from section '%s': %v", section.Name, err)
	}

	// Parse all entries
	var result []relocationItem
	reader := bytes.NewReader(data)

	for {
		var err error
		var offset, symbolIndex int

		switch elfFile.Class {
		case elf.ELFCLASS64:
			var rel elf.Rel64
			err = binary.Read(reader, elfFile.ByteOrder, &rel)
			// RELO.Info contains index of ELF SYMBOL which needs to be relocated.
			// P.S. "-1" because of: https://golang.org/pkg/debug/elf/#File.Symbols
			// 		For compatibility with Go 1.0, Symbols omits the null symbol at index 0.
			// 		After retrieving the symbols as symtab, an externally supplied
			// 		index x corresponds to symtab[x-1], not symtab[x].
			symbolIndex = int(elf.R_SYM64(rel.Info)) - 1
			offset = int(rel.Off)
		case elf.ELFCLASS32:
			var rel elf.Rel32
			err = binary.Read(reader, elfFile.ByteOrder, &rel)
			symbolIndex = int(elf.R_SYM32(rel.Info)) - 1
			offset = int(rel.Off)
		default:
			return nil, fmt.Errorf("Unsupported arch %v", elfFile.Class)
		}
		// Handle binary reader errors in one place
		if err == io.EOF {
			// No more relocations
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		// Ensure that symbol exists
		if symbolIndex >= len(symbols) {
			return nil, fmt.Errorf("Invalid RELO '%v': symbol index %v does not exist",
				section, symbolIndex)
		}
		result = append(result, relocationItem{
			offset: offset,
			symbol: symbols[symbolIndex],
		})
	}
}

func loadAndCreateMaps(elfFile *elf.File) (map[string]Map, error) {
	// Read ELF symbols
	// 获取ELF符号表 SHT_SYMTAB
	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("elf.Symbols() failed: %v", err)
	}

	// Lookup for "maps" ELF section
	var mapSection *elf.Section
	var mapSectionIndex int
	// 遍历所有节，检索名称为'maps'的节
	// MapSectionName = "maps"
	for index, section := range elfFile.Sections {
		if section.Name == MapSectionName {
			mapSection = section
			mapSectionIndex = index
		}
	}
	if mapSection == nil {
		// 可以存在么有map的ebpf程序
		// eBPF programs may live without maps - not an error
		return map[string]Map{}, nil
	}

	// Read and parse map definitions from designated ELF section
	// 解析'maps'节数据
	// EbpfMap 是每个map的描述符，这里就需要从elf maps节中提取数据构造
	mapsByIndex := []*EbpfMap{}
	// maps 节是有规则的，每个map固定大小
	data, err := mapSection.Data()
	if err != nil {
		return nil, fmt.Errorf("Failed to read '%s' section data: %v", mapSection.Name, err)
	}
	// 根据固定大小解析maps节
	for offset := 0; offset < len(data); offset += mapDefinitionSize {
		// 从头开始每 mapDefinitionSize 大小，解析成EbpfMap结构
		singleMap, err := newMapFromElfSection(data[offset:])
		if err != nil {
			return nil, err
		}
		// 下面是填充名称，elf中Name是数值，间接通过符号表获取string，这里在构造描述符时候直接转换了
		// Retrieve map name by looking up symbols table:
		// Each symbol contains section index and arbitrary value which for our case
		// is offset in section's data
		for _, sym := range symbols {
			if int(sym.Section) == mapSectionIndex && int(sym.Value) == offset {
				singleMap.Name = sym.Name
				break
			}
		}
		// sanity check，如果字符为空，则报错
		if singleMap.Name == "" {
			return nil, fmt.Errorf("Unable to get map name (section offset=%d)", offset)
		}
		mapsByIndex = append(mapsByIndex, singleMap)
	}

	// 处理重定位问题 如果定义了 const char *persistent_path; 则会用到这里
	// Process ELF relocations (RELO) - in order to read C strings. Given simple map definition:
	// BPF_MAP_DEF(progs) = {
	// 		.map_type = BPF_MAP_TYPE_PROG_ARRAY,
	// 		.max_entries = PROG_CNT,
	//      .persistent_path = "/sys/fs/bpf/txcnt",
	// };
	// BPF_MAP_ADD(progs);
	//
	// The problem here is compiler at compile time don't know address of constant string
	// so it puts NULL as value for ".persistent_path" and creates RELO entry that
	// tells loader that at given section / offset value must be replaced with address of
	// string which compiler saved into ELF symbol table.

	// Iterate over all sections in order to find all relocations for map's section
	for _, reloSection := range elfFile.Sections {
		// Skip unwanted sections
		if reloSection.Type != elf.SHT_REL || int(reloSection.Info) != mapSectionIndex {
			Debug("skip parse relocations")
			continue
		}
		fmt.Println("WARNNING，parse relocations")
		relocations, err := readRelocations(elfFile, reloSection)
		for index, item := range relocations {
			Debug("[%d] %x", index, item)
		}
		if err != nil {
			return nil, fmt.Errorf("readRelocations() failed: %v", err)
		}
		// Apply each RELO entry
		for _, relo := range relocations {
			// relocation's offset points to map's structure member offset which needs to be relocated
			mapOffset := relo.offset % mapDefinitionSize
			mapIndex := relo.offset / mapDefinitionSize
			if mapIndex >= len(mapsByIndex) {
				return nil, fmt.Errorf("Invalid RELO: map with index %d does not exist", mapIndex)
			}
			if mapOffset == mapDefinitionInnerMapOffset {
				// RELO for
				// 	  void *inner_map_def;
				// Symbol name is actually variable name ("inner_map_def" for given example)
				mapsByIndex[mapIndex].InnerMapName = relo.symbol.Name
			} else if mapOffset == mapDefinitionPersistentOffset {
				// RELO for
				//    const char  *persistent_path;
				// Since it points to string - reading it value from section
				// where this REL points to
				sec := elfFile.Sections[relo.symbol.Section]
				sdata, err := sec.Data()
				if err != nil {
					return nil, fmt.Errorf("Unable to read '%s' section data: %v", sec.Name, err)
				}
				// Section data contains null terminated string and
				// symbol.Value holds offset in this data
				mapsByIndex[mapIndex].PersistentPath = NullTerminatedStringToString(sdata[relo.symbol.Value:])
			} else {
				return nil, fmt.Errorf("Unknown map RELO offset %d", mapOffset)
			}
		}
	}

	// Create maps / add to result map
	// 这里Map是接口，EbpfMap是接口实例
	// 此处创建一个map名称->map描述符的映射关系，方便后续访问
	// 栈逃逸
	result := map[string]Map{}
	for _, item := range mapsByIndex {
		// Map of maps use case， Only for array/hash of maps
		if item.InnerMapName != "" {
			if innerMap, ok := result[item.InnerMapName]; ok {
				item.InnerMapFd = innerMap.GetFd()
			} else {
				return nil, fmt.Errorf("Inner map '%s' does not exist", item.InnerMapName)
			}
		}
		// Create map in kernel / add to results
		// 通过系统调用实现map创建
		err := item.Create()
		if err != nil {
			return nil, fmt.Errorf("map.Create() failed: %v", err)
		}
		result[item.Name] = item
	}
	return result, nil
}

func loadPrograms(elfFile *elf.File, maps map[string]Map) (map[string]Program, error) {
	// Read ELF symbols
	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("elf.Symbols() failed: %v", err)
	}

	// Find license information
	license := ""
	for _, section := range elfFile.Sections {
		if section.Name == LicenseSectionName {
			data, err := section.Data()
			if err != nil {
				return nil, fmt.Errorf("Failed to read data for section %s: %v", section.Name, err)
			}
			license = NullTerminatedStringToString(data)
			break
		}
	}

	// Iterate over all ELF section in order to find known sections with eBPF programs
	result := make(map[string]Program)
	for sectionIndex, section := range elfFile.Sections {

		// eBPF programs always sit in PROGBITS sections, so skip others
		if section.Type != elf.SHT_PROGBITS {
			continue
		}

		// Parse program type from section (everything before a '/' delimiter)
		progType := strings.ToLower(strings.Split(section.Name, "/")[0])

		// Ensure that this section is known
		createProgram, ok := sectionNameToProgramType[progType]
		if !ok {
			continue
		}

		// Read section data - it contains compiled bytecode of ALL programs
		bytecode, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("Failed to read data for section %s: %v", section.Name, err)
		}

		// Apply all relocations
		for _, reloSection := range elfFile.Sections {
			// Skip unwanted sections
			if reloSection.Type != elf.SHT_REL || int(reloSection.Info) != sectionIndex {
				continue
			}
			relocations, err := readRelocations(elfFile, reloSection)
			if err != nil {
				return nil, fmt.Errorf("readRelocations() failed: %v", err)
			}
			// Apply each relocation item
			for _, relocation := range relocations {
				// Get index of BPF instruction, then check it
				if relocation.offset >= len(bytecode) {
					return nil, fmt.Errorf("Invalid RELO offset %d", relocation.offset)
				}
				// Load BPF instruction that needs to be modified ("relocated")
				instruction := &bpfInstruction{}
				err = instruction.load(bytecode[relocation.offset:])
				if err != nil {
					return nil, err
				}
				// Ensure that instruction is valid
				if instruction.code != (unix.BPF_LD | unix.BPF_IMM | bpfDw) {
					return nil, fmt.Errorf("Invalid BPF instruction (at %d): %v",
						relocation.offset, instruction)
				}
				// Patch instruction to use proper map fd
				mapName := relocation.symbol.Name
				if bpfMap, ok := maps[mapName]; ok {
					instruction.srcReg = bpfPseudoMapFd
					instruction.imm = uint32(bpfMap.GetFd())
					copy(bytecode[relocation.offset:], instruction.save())
				} else {
					return nil, fmt.Errorf("map '%s' doesn't exist", mapName)
				}
			}
		}

		// One section may contain multiple programs.
		// Find all programs and their offsets from symbols table, then
		// reverse sort them by offset (since order is not guaranteed!)
		offsetToNameMap := map[int]string{}
		offsetToNameKeys := []int{} // For keys sort
		for _, symbol := range symbols {
			if int(symbol.Section) == sectionIndex && elf.ST_BIND(symbol.Info) == elf.STB_GLOBAL {
				key := int(symbol.Value)
				offsetToNameMap[key] = symbol.Name
				offsetToNameKeys = append(offsetToNameKeys, key)
			}
			// Skip others
		}

		// Slice eBPF programs by reverse sorted offsets from symbol table
		sort.Sort(sort.Reverse(sort.IntSlice(offsetToNameKeys)))
		lastOffset := len(bytecode)
		for _, offset := range offsetToNameKeys {
			name := offsetToNameMap[offset]
			size := lastOffset - offset
			// Create Program instance with type based on section name (e.g. XDP)
			result[name] = createProgram(BaseProgram{
				name:     name,
				section:  section.Name,
				license:  license,
				bytecode: bytecode[offset : offset+size],
			})
			lastOffset = offset
		}
	}

	return result, nil
}

// LoadElf reads ELF file compiled by clang + llvm for target bpf
func (s *ebpfSystem) LoadElf(path string) error {
	// 打开ELF文件句柄
	// func Open(name string) (*File, error)
	// 默认权限 O_RDONLY ，若文件不存不会创建
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// 关键点
	return s.Load(f)
}

// Load reads ELF file compiled by clang + llvm for target bpf
// 加载ELF程序
func (s *ebpfSystem) Load(r io.ReaderAt) error {
	// Read ELF headers 使用内置库elf解析
	// 读取ELF头、program头、section头信息
	// func NewFile(r io.ReaderAt) (*File, error)
	Debug("Create elf file handler")
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return err
	}

	// Load eBPF maps
	// 通过系统调用创建map并返回句柄
	Debug("load and create maps")
	s.Maps, err = loadAndCreateMaps(elfFile)
	if err != nil {
		return fmt.Errorf("loadAndCreateMaps() failed: %v", err)
	}

	// Load eBPF programs
	Debug("load programs")
	s.Programs, err = loadPrograms(elfFile, s.Maps)
	if err != nil {
		return fmt.Errorf("loadPrograms() failed: %v", err)
	}

	return nil
}
