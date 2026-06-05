//go:build !windows

package main

func decodeVerificationOutputBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return string(data)
}
