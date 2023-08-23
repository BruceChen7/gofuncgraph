package elf

import "debug/elf"

func (e *ELF) FindGOffset() (offset int64, err error) {
	_, symnames, err := e.Symbols()
	if err != nil {
		return
	}
	tlsg, tlsgExists := symnames["runtime.tlsg"]
	// programe header
	tls := e.Prog(elf.PT_TLS)
	// 符号处在，并且存在tls block
	// 在 Go ELF 二进制文件中， runtime.tlsg 指的是 goroutine 的线程本地存储 (TLS) block。
	// TLS 是一种允许程序的每个线程拥有自己的私有数据的机制。
	// runtime.tlsg 符号表示 TLS 块在可执行文件中的符号信息
	if tlsgExists && tls != nil {
		// 对齐
		memsz := tls.Memsz + (-tls.Vaddr-tls.Memsz)&(tls.Align-1)
		// 取反 + 1 +
		return int64(^(memsz) + 1 + tlsg.Value), nil
	}
	return -8, nil
}
