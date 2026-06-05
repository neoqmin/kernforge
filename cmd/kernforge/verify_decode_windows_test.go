//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestVerificationOutputTextDecodesCP949OnWindows(t *testing.T) {
	raw := []byte{
		'S', 'o', 'u', 'r', 'c', 'e', '\\', 'W', 'o', 'r', 'k', 'e', 'r', '.', 'c', 'p', 'p',
		'(', '4', '2', ')', ':', ' ',
		0xbf, 0xc0, 0xb7, 0xf9,
		' ', 'C', '2', '0', '6', '5', ':', ' ', 'x',
	}
	got := verificationOutputText(raw)
	if !strings.Contains(got, "오류 C2065") {
		t.Fatalf("expected CP949 verification output to decode, got %q", got)
	}
}
