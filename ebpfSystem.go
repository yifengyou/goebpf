// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

const (
	// Maximum buffer size for kernel's eBPF verifier error log messages
	logBufferSize = (256 * 1024)
)

// System implementation
type ebpfSystem struct {
	Programs map[string]Program // eBPF programs by name
	Maps     map[string]Map     // eBPF maps defined by Progs by name
}

// NewDefaultEbpfSystem creates default eBPF system
// 返回接口
func NewDefaultEbpfSystem() System {
	// 实例化，待填充内容
	return &ebpfSystem{
		Programs: make(map[string]Program),
		Maps:     make(map[string]Map),
	}
}

// GetMaps returns all maps found in .elf file
func (s *ebpfSystem) GetMaps() map[string]Map {
	return s.Maps
}

// GetPrograms returns all eBPF programs found in .elf file
func (s *ebpfSystem) GetPrograms() map[string]Program {
	return s.Programs
}

// GetMapByName returns eBPF map by given name
func (s *ebpfSystem) GetMapByName(name string) Map {
	if result, ok := s.Maps[name]; ok {
		return result
	}
	return nil
}

// GetProgramByName returns eBPF program by given name
func (s *ebpfSystem) GetProgramByName(name string) Program {
	if result, ok := s.Programs[name]; ok {
		return result
	}
	return nil
}
