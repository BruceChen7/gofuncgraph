package bpf

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/ufuncgraph/internal/uprobe"
	dynamicstruct "github.com/ompluscator/dynamic-struct"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event Ufuncgraph ./ufuncgraph.c -- -I./headers

const (
	EventDataOffset int64 = 436
	VacantR10Offset       = -96
)

type BPF struct {
	executables map[string]*link.Executable
	objs        interface{}
	closers     []io.Closer
}

func New() *BPF {
	return &BPF{
		executables: map[string]*link.Executable{},
	}
}

func (b *BPF) Load(uprobes []uprobe.Uprobe) (err error) {
	structDefine := dynamicstruct.NewStruct().
		AddField("GoEnt", &ebpf.Program{}, `ebpf:"go_ent"`).
		AddField("GoEntBt", &ebpf.Program{}, `ebpf:"go_ent_bt"`).
		AddField("CEnt", &ebpf.Program{}, `ebpf:"c_ent"`).
		AddField("CEntBt", &ebpf.Program{}, `ebpf:"c_ent_bt"`).
		AddField("GoRet", &ebpf.Program{}, `ebpf:"go_ret"`).
		AddField("CRet", &ebpf.Program{}, `ebpf:"c_ret"`).
		AddField("BpfStack", &ebpf.Map{}, `ebpf:"bpf_stack"`).
		AddField("EventQueue", &ebpf.Map{}, `ebpf:"event_queue"`).
		AddField("Goids", &ebpf.Map{}, `ebpf:"goids"`)

	spec, err := LoadUfuncgraph()
	if err != nil {
		return err
	}

	for _, up := range uprobes {
		if up.Location != uprobe.AtFramePointer || len(up.FetchArgs) == 0 {
			continue
		}
		fieldPrefix, progPrefix := "GoEnt", "go_ent"
		if up.Backtrace {
			fieldPrefix, progPrefix = "GoEntBt", "go_ent_bt"
		}
		suffix := fmt.Sprintf("_%x", up.Offset)
		progName := progPrefix + suffix
		structDefine.AddField(fieldPrefix+suffix, &ebpf.Program{}, fmt.Sprintf(`ebpf:"%s"`, progName))
		spec.Programs[progName] = spec.Programs[progPrefix].Copy()
		instructions := []asm.Instruction{}
		eventOffset := EventDataOffset
		for _, args := range up.FetchArgs {
			instructions = append(instructions, args.CompileBpfInstructions(VacantR10Offset, eventOffset)...)
			eventOffset += int64(args.Size)
		}

		bpfInsertIndex := 0
		for bpfInsertIndex = range spec.Programs[progName].Instructions {
			inst := spec.Programs[progName].Instructions[bpfInsertIndex]
			if inst.OpCode == 123 && inst.Dst == asm.R6 && inst.Src == asm.R1 && inst.Offset == 0 {
				break
			}
		}
		bpfInsertIndex++

		spec.Programs[progName].Instructions = append(spec.Programs[progName].Instructions[:bpfInsertIndex], append(instructions, spec.Programs[progName].Instructions[bpfInsertIndex:]...)...)

		for i, ins := range spec.Programs[progName].Instructions {
			if ins.OpCode == 21 { // goto
				if i < bpfInsertIndex {
					spec.Programs[progName].Instructions[i].Offset += int16(len(instructions))
				}
			}
		}
	}
	b.objs = structDefine.Build().New()

	defer func() {
		if err != nil {
			return
		}
		reader := dynamicstruct.NewReader(b.objs)
		b.closers = append(b.closers, reader.GetField("EventQueue").Interface().(*ebpf.Map))
		b.closers = append(b.closers, reader.GetField("BpfStack").Interface().(*ebpf.Map))
		b.closers = append(b.closers, reader.GetField("Goids").Interface().(*ebpf.Map))
	}()
	return spec.LoadAndAssign(b.objs, nil)
}

func (b *BPF) Attach(bin string, uprobes []uprobe.Uprobe) (err error) {
	ex, err := link.OpenExecutable(bin)
	if err != nil {
		return
	}
	reader := dynamicstruct.NewReader(b.objs)
	for _, up := range uprobes {
		var prog *ebpf.Program
		switch up.Location {
		case uprobe.AtFramePointer:
			suffix := ""
			if len(up.FetchArgs) > 0 {
				suffix = fmt.Sprintf("_%x", up.Offset)
			}
			if up.Backtrace {
				prog = reader.GetField("GoEntBt" + suffix).Interface().(*ebpf.Program)
			} else {
				prog = reader.GetField("GoEnt" + suffix).Interface().(*ebpf.Program)
			}
		case uprobe.AtRet:
			prog = reader.GetField("GoRet").Interface().(*ebpf.Program)
		}
		up, err := ex.Uprobe("", prog, &link.UprobeOptions{Offset: up.Offset})
		if err != nil {
			return err
		}
		b.closers = append(b.closers, up)

	}
	return
}

func (b *BPF) Detach() {
	for _, closer := range b.closers {
		closer.Close()
	}
}

func (b *BPF) PollEvents(ctx context.Context) chan UfuncgraphEvent {
	ch := make(chan UfuncgraphEvent)

	queue := dynamicstruct.NewReader(b.objs).GetField("EventQueue").Interface().(*ebpf.Map)
	go func() {
		defer close(ch)
		for {
			event := UfuncgraphEvent{}
			select {
			case <-ctx.Done():
				return
			default:
				if err := queue.LookupAndDelete(nil, &event); err != nil {
					time.Sleep(time.Millisecond)
					continue
				}
				ch <- event
			}
		}
	}()
	return ch
}
