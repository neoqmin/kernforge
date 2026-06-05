//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var kernel32VerifyDecodeDLL = syscall.NewLazyDLL("kernel32.dll")
var multiByteToWideCharVerifyProc = kernel32VerifyDecodeDLL.NewProc("MultiByteToWideChar")

func decodeVerificationOutputBytes(data []byte) string {
	for _, codePage := range []uint32{949, 0, 1} {
		if decoded := decodeVerificationOutputWithCodePage(data, codePage); decoded != "" {
			return decoded
		}
	}
	return ""
}

func decodeVerificationOutputWithCodePage(data []byte, codePage uint32) string {
	if len(data) == 0 {
		return ""
	}
	size, _, _ := multiByteToWideCharVerifyProc.Call(
		uintptr(codePage),
		0,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0,
		0,
	)
	if size == 0 {
		return ""
	}
	buf := make([]uint16, size)
	written, _, _ := multiByteToWideCharVerifyProc.Call(
		uintptr(codePage),
		0,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&buf[0])),
		size,
	)
	if written == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:written])
}
