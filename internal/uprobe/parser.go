package uprobe

import (
	"bytes"
	debugelf "debug/elf"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jschwinger233/gofuncgraph/elf"
	log "github.com/sirupsen/logrus"
)

type ParseOptions struct {
	ExcludeVendor   bool
	UprobeWildcards []string
	OutputWildcards []string
	// 获取变量信息
	Fetch map[string]map[string]string // funcname: varname: expression
}

func Parse(elf *elf.ELF, opts *ParseOptions) (uprobes []Uprobe, err error) {
	fetchArgs, err := parseFetchArgs(opts.Fetch)
	if err != nil {
		return
	}

	// 从elf中获取符号信息
	symbols, _, err := elf.Symbols()
	if err != nil {
		return
	}

	wantedFuncs := map[string]interface{}{}
	attachFuncs := []string{}
	// 读取符号信息
	for _, symbol := range symbols {
		// 获取符号的类型信息
		fmt.Fprintf(os.Stdout, "symbol: %v\n", symbol)
		if debugelf.ST_TYPE(symbol.Info) == debugelf.STT_FUNC {
			for _, wc := range append(opts.UprobeWildcards, opts.OutputWildcards...) {
				fmt.Printf("wildcard: %v\n", wc)
				if MatchWildcard(wc, symbol.Name) {
					if opts.ExcludeVendor && strings.Contains(symbol.Name, "/vendor/") {
						continue
					}
					attachFuncs = append(attachFuncs, symbol.Name)
					if len(opts.OutputWildcards) == 0 {
						wantedFuncs[symbol.Name] = true
					} else {
						for _, wc := range opts.OutputWildcards {
							if MatchWildcard(wc, symbol.Name) {
								wantedFuncs[symbol.Name] = true
								break
							}
						}
					}
					break
				}
			}
		}
	}

	log.Debugf("wantedFuncs: %v, attachFuncs: %v", wantedFuncs, attachFuncs)

	sym, err := elf.ResolveSymbol("runtime.goexit1")
	if err != nil {
		return nil, err
	}
	entOffset, err := elf.FuncOffset("runtime.goexit1")
	if err != nil {
		return nil, err
	}
	// 添加runtime.goexit1的uprobes
	uprobes = append(uprobes, Uprobe{
		Funcname:  "runtime.goexit1",
		Location:  AtGoroutineExit,
		Address:   sym.Value,
		AbsOffset: entOffset,
	})

	for _, funcname := range attachFuncs {
		message := &bytes.Buffer{}
		fmt.Fprintf(message, "add uprobes for %s: ", funcname)
		// 获取符号
		sym, err := elf.ResolveSymbol(funcname)
		if err != nil {
			return nil, err
		}
		// 获取符号在text的偏移
		entOffset, err := elf.FuncOffset(funcname)
		if err != nil {
			return nil, err
		}
		_, wanted := wantedFuncs[funcname]
		fmt.Fprintf(message, "0x%x -> ", entOffset)
		uprobes = append(uprobes, Uprobe{
			Funcname: funcname,
			Location: AtEntry,
			Address:  sym.Value,
			// 这个是绝对偏移量
			AbsOffset: entOffset,
			// 相对偏移量
			RelOffset: 0,
			// 写这个数据
			FetchArgs: fetchArgs[funcname],
			Wanted:    wanted,
		})

		retOffsets, err := elf.FuncRetOffsets(funcname)
		if err == nil && len(retOffsets) == 0 {
			err = errors.New("no ret offsets")
		}
		if err != nil {
			log.Warnf("skip %s, failed to get ret offsets: %v", funcname, err)
			uprobes = uprobes[:len(uprobes)-1]
			continue
		}
		fmt.Fprintf(message, "[ ")
		for _, retOffset := range retOffsets {
			fmt.Fprintf(message, "0x%x ", retOffset)
			uprobes = append(uprobes, Uprobe{
				Funcname:  funcname,
				Location:  AtRet,
				AbsOffset: retOffset,
				RelOffset: retOffset - entOffset,
			})
		}
		fmt.Fprintf(message, "]")
		if wanted {
			fmt.Fprintf(message, " *")
		}
		fmt.Fprintf(message, "\n")
		log.Debug(message.String())
	}
	return
}
