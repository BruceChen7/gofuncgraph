package eventmanager

import (
	"errors"
	"fmt"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/jschwinger233/gofuncgraph/elf"
	"github.com/jschwinger233/gofuncgraph/internal/bpf"
	"github.com/jschwinger233/gofuncgraph/internal/uprobe"
	log "github.com/sirupsen/logrus"
)

type Event struct {
	bpf.GofuncgraphEvent
	uprobe    *uprobe.Uprobe
	argString string
}

type EventManager struct {
	elf     *elf.ELF
	argCh   <-chan bpf.GofuncgraphArgData
	uprobes map[string]uprobe.Uprobe

	// key 是goroutine id
	goEvents map[uint64][]Event
	// key is Goid， value is 入口和出口匹配情况
	goEventStack map[uint64]uint64
	goArgs       map[uint64]chan bpf.GofuncgraphArgData

	bootTime time.Time
}

func New(uprobes []uprobe.Uprobe, elf *elf.ELF, ch <-chan bpf.GofuncgraphArgData) (_ *EventManager, err error) {
	// 返回主机信息
	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	// 启动时间
	bootTime := host.Info().BootTime
	uprobesMap := map[string]uprobe.Uprobe{}
	for _, up := range uprobes {
		// 偏移量
		uprobesMap[fmt.Sprintf("%s+%d", up.Funcname, up.RelOffset)] = up
	}
	m := &EventManager{
		elf:          elf,
		argCh:        ch,
		uprobes:      uprobesMap,
		goEvents:     map[uint64][]Event{},
		goEventStack: map[uint64]uint64{},
		goArgs:       map[uint64]chan bpf.GofuncgraphArgData{},
		bootTime:     bootTime,
	}
	go m.handleArg()
	return m, err
}

func (m *EventManager) handleArg() {
	for arg := range m.argCh {
		if _, ok := m.goArgs[arg.Goid]; !ok {
			m.goArgs[arg.Goid] = make(chan bpf.GofuncgraphArgData, 1000)
		}
		log.Debugf("add arg %+v", arg)
		m.goArgs[arg.Goid] <- arg
	}
}

func (m *EventManager) GetUprobe(event bpf.GofuncgraphEvent) (_ uprobe.Uprobe, err error) {
	// 运行的指令
	syms, offset, err := m.elf.ResolveAddress(event.Ip)
	if err != nil {
		return
	}
	for _, sym := range syms {
		uprobe, ok := m.uprobes[fmt.Sprintf("%s+%d", sym.Name, offset)]
		if ok {
			return uprobe, nil
		}
	}
	err = errors.New("uprobe not found")
	return
}
