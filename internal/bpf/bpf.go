package bpf

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/gofuncgraph/internal/uprobe"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event -type arg_rules -type arg_rule -type arg_data Gofuncgraph ./gofuncgraph.c -- -I./headers

const (
	EventDataOffset int64 = 436
	VacantR10Offset       = -96
)

var RegisterConstants = map[string]uint8{
	"ax":  0,
	"dx":  1,
	"cx":  2,
	"bx":  3,
	"si":  4,
	"di":  5,
	"bp":  6,
	"sp":  7,
	"r8":  8,
	"r9":  9,
	"r10": 10,
	"r11": 11,
	"r12": 12,
	"r13": 13,
	"r14": 14,
	"r15": 15,
}

type LoadOptions struct {
	GoidOffset int64
	GOffset    int64
}

type BPF struct {
	objs    *GofuncgraphObjects
	closers []io.Closer
}

func New() *BPF {
	return &BPF{}
}

func (b *BPF) BpfConfig(fetchArgs bool, goidOffset, gOffset int64) interface{} {
	return struct {
		GoidOffset, GOffset int64
		// 是否获取参数信息
		FetchArgs bool
		Padding   [7]byte
	}{
		GoidOffset: goidOffset,
		GOffset:    gOffset,
		FetchArgs:  fetchArgs,
	}
}

func (b *BPF) Load(uprobes []uprobe.Uprobe, opts LoadOptions) (err error) {
	spec, err := LoadGofuncgraph()
	if err != nil {
		return err
	}

	b.objs = &GofuncgraphObjects{}
	defer func() {
		if err != nil {
			return
		}
		// close event queue
		b.closers = append(b.closers, b.objs.EventQueue)
		// close event stack
		b.closers = append(b.closers, b.objs.EventStack)
	}()

	fetchArgs := false
	for _, uprobe := range uprobes {
		if len(uprobe.FetchArgs) > 0 {
			fetchArgs = true
			break
		}
	}
	// 用来重新写C 语言二进制常量
	if err = spec.RewriteConstants(map[string]interface{}{"CONFIG": b.BpfConfig(fetchArgs, opts.GoidOffset, opts.GOffset)}); err != nil {
		log.Errorf("rewrite constants failed: %v", err)
		return
	}
	if err = spec.LoadAndAssign(b.objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSize: ebpf.DefaultVerifierLogSize * 4},
	}); err != nil {
		log.Errorf("load and assign failed: %v", err)
		return
	}

	for _, uprobe := range uprobes {
		if len(uprobe.FetchArgs) > 0 {
			if err = b.setArgRules(uprobe.Address, uprobe.FetchArgs); err != nil {
				return
			}
		}
		if uprobe.Wanted {
			if err = b.setWanted(uprobe); err != nil {
				return
			}
		}
	}
	return
}

func (b *BPF) setArgRules(pc uint64, fetchArgs []*uprobe.FetchArg) (err error) {
	if len(fetchArgs) > 8 {
		return fmt.Errorf("too many fetch args: %d > 8", len(fetchArgs))
	}
	argRules := GofuncgraphArgRules{Length: uint8(len(fetchArgs))}
	for idx, fetchArg := range fetchArgs {
		if len(fetchArg.Rules) > 8 {
			return fmt.Errorf("too many rules: %d > 8", len(fetchArg.Rules))
		}
		rule := GofuncgraphArgRule{
			Type:   uint8(fetchArg.Rules[len(fetchArg.Rules)-1].From),
			Reg:    RegisterConstants[fetchArg.Rules[0].Register],
			Size:   uint8(fetchArg.Size),
			Length: uint8(len(fetchArg.Rules) - 1),
		}

		j := 0
		for _, r := range fetchArg.Rules {
			if r.From == uprobe.Stack {
				rule.Offsets[j] = int16(r.Offset)
				j++
			}
		}
		argRules.Rules[idx] = rule
		fmt.Printf("add arg rule at %x: %+v\n", pc, rule)
	}
	return b.objs.ArgRulesMap.Update(pc, argRules, ebpf.UpdateNoExist)
}

func (b *BPF) setWanted(uprobe uprobe.Uprobe) (err error) {
	return b.objs.ShouldTraceRip.Update(uprobe.Address, true, ebpf.UpdateNoExist)
}

func (b *BPF) Attach(bin string, uprobes []uprobe.Uprobe) (err error) {
	log.Infof("start attaching %s", bin)
	ex, err := link.OpenExecutable(bin)
	if err != nil {
		fmt.Printf("open %s failed: %v\n", bin, err)
		return
	}
	for i, up := range uprobes {
		// fmt.Printf("attaching %d/%v\n", i, up)
		var prog *ebpf.Program
		var linkOption link.UprobeOptions
		uprobeName := ""
		switch up.Location {
		case uprobe.AtEntry:
			prog = b.objs.Ent
			log.Infof("attach entry programe address: symbol name %s, absolute %x\n", up.Funcname, up.Address)
			uprobeName = up.Funcname
		case uprobe.AtRet:
			prog = b.objs.Ret
			log.Infof("attach ret programe\n")
			// 相对符号的偏移量
			uprobeName = up.Funcname
			linkOption.Offset = up.RelOffset
		case uprobe.AtGoroutineExit:
			uprobeName = up.Funcname
			log.Infof("use goroutine exit programe\n")
			prog = b.objs.GoroutineExit
		}
		log.Infof("attaching %d symbol %s relative addr %x absoluet addr %x addr %x\n", i, up.Funcname, up.RelOffset, up.AbsOffset, up.Address)
		up, err := ex.Uprobe(uprobeName, prog, &linkOption)
		if err != nil {
			log.Errorf("attach failed: %v, upprobe %v", err, up)
			return err
		}
		log.Infof("attaching success")
		b.closers = append(b.closers, up)

	}
	return
}

func (b *BPF) Detach() {
	log.Info("start detaching\n")
	sem := semaphore.NewWeighted(10)
	for i, closer := range b.closers {
		fmt.Printf("detaching %d/%d\r", i+1, len(b.closers))
		sem.Acquire(context.Background(), 1)
		go func(closer io.Closer) {
			defer sem.Release(1)
			closer.Close()
		}(closer)
	}
	fmt.Println()
}

func (b *BPF) PollEvents(ctx context.Context) chan GofuncgraphEvent {
	ch := make(chan GofuncgraphEvent)

	go func() {
		defer close(ch)
		for {
			event := GofuncgraphEvent{}
			select {
			case <-ctx.Done():
				return
			default:
				// 从event queue中获取远程trace
				if err := b.objs.EventQueue.LookupAndDelete(nil, &event); err != nil {
					time.Sleep(time.Millisecond)
					continue
				}
				ch <- event
			}
		}
	}()
	return ch
}

func (b *BPF) PollArg(ctx context.Context) <-chan GofuncgraphArgData {
	ch := make(chan GofuncgraphArgData)
	go func() {
		defer close(ch)
		for {
			data := GofuncgraphArgData{}
			select {
			case <-ctx.Done():
				return
			default:
				if err := b.objs.ArgQueue.LookupAndDelete(nil, &data); err != nil {
					time.Sleep(time.Millisecond)
					continue
				}
				ch <- data
			}

		}
	}()
	return ch
}
