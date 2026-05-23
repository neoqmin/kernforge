//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

const (
	stdOutputHandle                 = ^uint32(10)
	stdErrorHandle                  = ^uint32(11)
	invalidHandleValue              = ^uintptr(0)
	enableProcessedOutput           = 0x0001
	enableVirtualTerminalProcessing = 0x0004
)

var (
	kernel32TerminalVTDLL = syscall.NewLazyDLL("kernel32.dll")
	getStdHandleVTProc    = kernel32TerminalVTDLL.NewProc("GetStdHandle")
	getConsoleModeVTProc  = kernel32TerminalVTDLL.NewProc("GetConsoleMode")
	setConsoleModeVTProc  = kernel32TerminalVTDLL.NewProc("SetConsoleMode")
)

func ensureVirtualTerminalProcessing() {
	enableVirtualTerminalProcessingForHandle(stdOutputHandle)
	enableVirtualTerminalProcessingForHandle(stdErrorHandle)
}

func enableVirtualTerminalProcessingForHandle(stdHandle uint32) {
	handle, _, _ := getStdHandleVTProc.Call(uintptr(stdHandle))
	if handle == 0 || handle == invalidHandleValue {
		return
	}

	var mode uint32
	ok, _, _ := getConsoleModeVTProc.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if ok == 0 {
		return
	}

	requested := uint32(enableProcessedOutput | enableVirtualTerminalProcessing)
	if mode&requested == requested {
		return
	}

	setConsoleModeVTProc.Call(handle, uintptr(mode|requested))
}
