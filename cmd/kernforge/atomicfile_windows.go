//go:build windows

package main

import (
	"syscall"
	"time"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
	replaceFileMaxAttempts  = 8
	errorSharingViolation   = syscall.Errno(32)
	errorLockViolation      = syscall.Errno(33)
)

func replaceFileAtomic(src, dst string) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	moveFileExW := kernel32.NewProc("MoveFileExW")
	srcPtr, err := syscall.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	dstPtr, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < replaceFileMaxAttempts; attempt++ {
		r1, _, callErr := moveFileExW.Call(
			uintptr(unsafe.Pointer(srcPtr)),
			uintptr(unsafe.Pointer(dstPtr)),
			uintptr(moveFileReplaceExisting|moveFileWriteThrough),
		)
		if r1 != 0 {
			return nil
		}
		lastErr = syscall.EINVAL
		if callErr != syscall.Errno(0) {
			lastErr = callErr
		}
		if !transientReplaceFileError(lastErr) {
			return lastErr
		}
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	return lastErr
}

func transientReplaceFileError(err error) bool {
	errno, ok := err.(syscall.Errno)
	if !ok {
		return false
	}
	switch errno {
	case syscall.ERROR_ACCESS_DENIED,
		errorSharingViolation,
		errorLockViolation:
		return true
	default:
		return false
	}
}
