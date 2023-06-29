package eventmanager

import (
	"fmt"
	"strconv"
	"time"

	"github.com/jschwinger233/gofuncgraph/internal/uprobe"
)

const placeholder = "        "

func (m *EventManager) SprintCallChain(event Event) (chain string, err error) {
	if event.CallerIp == 0 {
		return "", nil
	}
	syms, off, err := m.elf.ResolveAddress(event.CallerIp)
	if err != nil {
		return
	}
	return fmt.Sprintf("%s+%d", syms[0].Name, off), nil
}

func (m *EventManager) PrintStack(goid uint64) (err error) {
	indent := ""
	fmt.Println()
	startTimeStack := []uint64{}
	// 打印该goroutine的栈
	for _, event := range m.goEvents[goid] {
		lineInfo := "?:?"
		// 事件发生的时间
		t := m.bootTime.Add(time.Duration(event.TimeNs)).Format("02 15:04:05.0000")
		syms, offset, err := m.elf.ResolveAddress(event.Ip)
		if err != nil {
			return err
		}

		switch event.Location {
		case 0: // entpoint
			startTimeStack = append(startTimeStack, event.TimeNs)
			callChain, err := m.SprintCallChain(event)
			if err != nil {
				return err
			}
			// 源代码中的位置
			if filename, line, err := m.elf.LineInfoForPc(event.CallerIp); err == nil {
				lineInfo = fmt.Sprintf("%s:%d", filename, line)
			}

			fmt.Printf("%s %s %s %s(%s) { %s %s\n", t, placeholder, indent, event.uprobe.Funcname, event.argString, callChain, lineInfo)
			indent += "  "

		case 1: // retpoint
			if len(indent) == 0 {
				continue
			}
			// 源代码中的位置
			if filename, line, err := m.elf.LineInfoForPc(event.Ip); err == nil {
				lineInfo = fmt.Sprintf("%s:%d", filename, line)
			}
			// 函数调用的时间
			elapsed := event.TimeNs - startTimeStack[len(startTimeStack)-1]
			startTimeStack = startTimeStack[:len(startTimeStack)-1]
			indent = indent[:len(indent)-2]
			// 打印时间
			fmt.Printf("%s %08.4f %s } %s+%d %s\n", t, time.Duration(elapsed).Seconds(), indent, syms[0].Name, offset, lineInfo)
		}

	}
	return
}

func (m *EventManager) SprintArg(arg *uprobe.FetchArg, data []uint8) (_ string, err error) {
	value := arg.SprintValue(data)
	if arg.Varname != "__call__" {
		return fmt.Sprintf("%s=%s", arg.Varname, value), nil
	}
	addr, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return "", err
	}
	syms, offset, err := m.elf.ResolveAddress(addr)
	if err != nil {
		return "", err
	}
	if offset != 0 {
		return "", fmt.Errorf("not a valid __call__ target: %lld", addr)
	}
	return fmt.Sprintf("__call__=%s", syms[0].Name), nil
}

func (m *EventManager) PrintRemaining() (err error) {
	for goid := range m.goEvents {
		if err = m.PrintStack(goid); err != nil {
			break
		}
	}
	return
}
