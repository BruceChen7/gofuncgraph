package elf

import (
	"github.com/pkg/errors"
	"golang.org/x/arch/x86/x86asm"
)

func (e *ELF) FuncInstructions(name string) (insts []x86asm.Inst, addr, offset uint64, err error) {
	raw, addr, offset, err := e.FuncRawInstructions(name)
	if err != nil {
		return
	}
	// 传入
	return e.ResolveInstructions(raw), addr, offset, nil
}

// 找到相对.text段的返回地址
func (e *ELF) FuncRetOffsets(name string) (offsets []uint64, err error) {
	// 符号相对section的offset
	insts, _, offset, err := e.FuncInstructions(name)
	if err != nil {
		return
	}

	// 遍历获取返回地址， 该地址是相对function entry point 的偏移
	// insts is the x86 instructions
	for _, inst := range insts {
		if inst.Op == x86asm.RET {
			offsets = append(offsets, offset)
		}
		offset += uint64(inst.Len)
	}
	return
}

func (e *ELF) FuncFramePointerOffset(name string) (offset uint64, err error) {
	insts, _, offset, err := e.FuncInstructions(name)
	if err != nil {
		return
	}

	bp := 0
	for _, inst := range insts {
		offset += uint64(inst.Len)
		for _, a := range inst.Args {
			if a != nil && a.String() == "RBP" {
				bp++
				if bp == 2 {
					return offset, nil
				}
			}
		}
	}
	return 0, errors.Wrap(FramePointerNotFoundErr, name)
}

func (e *ELF) ResolveInstructions(bytes []byte) (insts []x86asm.Inst) {
	if len(bytes) == 0 {
		return
	}
	for {
		inst, err := x86asm.Decode(bytes, 64)
		if err != nil {
			inst = x86asm.Inst{Len: 1}
		}
		insts = append(insts, inst)
		// 开始下一个byte的开始翻译
		bytes = bytes[inst.Len:]
		if len(bytes) == 0 {
			break
		}
	}
	return
}
