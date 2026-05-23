package main

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

type benchmarkImageSize struct {
	width  int
	height int
}

var (
	benchmarkSmallScreenshot = benchmarkImageSize{width: 1536, height: 864}
	benchmarkLargeScreenshot = benchmarkImageSize{width: 2560, height: 1440}
	benchmarkLargePhoto      = benchmarkImageSize{width: 3264, height: 2448}
)

func BenchmarkLoadImageForPromptSmallPNGScreenshot(b *testing.B) {
	benchmarkLoadImageForPrompt(b, "small-screenshot.png", benchmarkScreenshotPNG(b, benchmarkSmallScreenshot), imageDetailHigh)
}

func BenchmarkLoadImageForPromptLargePNGScreenshot(b *testing.B) {
	benchmarkLoadImageForPrompt(b, "large-screenshot.png", benchmarkScreenshotPNG(b, benchmarkLargeScreenshot), imageDetailHigh)
}

func BenchmarkLoadImageForPromptLargeJPEGPhoto(b *testing.B) {
	benchmarkLoadImageForPrompt(b, "large-photo.jpg", benchmarkPhotoJPEG(b, benchmarkLargePhoto), imageDetailHigh)
}

func BenchmarkLoadImageForPromptOriginalPNG(b *testing.B) {
	benchmarkLoadImageForPrompt(b, "original-screenshot.png", benchmarkScreenshotPNG(b, benchmarkSmallScreenshot), imageDetailOriginal)
}

func benchmarkLoadImageForPrompt(b *testing.B, name string, data []byte, detail string) {
	b.Helper()
	path := filepath.Join(b.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		b.Fatalf("write benchmark image: %v", err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := loadImageForPrompt(path, detail); err != nil {
			b.Fatalf("loadImageForPrompt: %v", err)
		}
	}
}

func benchmarkScreenshotPNG(b *testing.B, size benchmarkImageSize) []byte {
	b.Helper()
	img := image.NewRGBA(image.Rect(0, 0, size.width, size.height))
	for y := 0; y < size.height; y++ {
		for x := 0; x < size.width; x++ {
			toolbar := y < 52
			sidebar := x < 240
			panelBorder := x%320 < 2 || y%216 < 2
			textRow := x > 270 && y > 88 && x%19 < 13 && y%31 < 3
			switch {
			case toolbar:
				img.Set(x, y, color.RGBA{R: 33, G: 40, B: 52, A: 255})
			case sidebar:
				if y/68%5 == 2 {
					img.Set(x, y, color.RGBA{R: 65, G: 106, B: 171, A: 255})
				} else {
					img.Set(x, y, color.RGBA{R: 44, G: 54, B: 67, A: 255})
				}
			case panelBorder:
				img.Set(x, y, color.RGBA{R: 198, G: 205, B: 216, A: 255})
			case textRow:
				img.Set(x, y, color.RGBA{R: 72, G: 82, B: 96, A: 255})
			default:
				panel := ((x / 320) + (y/216)*3) % 4
				switch panel {
				case 0:
					img.Set(x, y, color.RGBA{R: 246, G: 248, B: 252, A: 255})
				case 1:
					img.Set(x, y, color.RGBA{R: 234, G: 241, B: 250, A: 255})
				case 2:
					img.Set(x, y, color.RGBA{R: 240, G: 247, B: 236, A: 255})
				default:
					img.Set(x, y, color.RGBA{R: 250, G: 240, B: 235, A: 255})
				}
			}
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		b.Fatalf("encode benchmark png: %v", err)
	}
	return out.Bytes()
}

func benchmarkPhotoJPEG(b *testing.B, size benchmarkImageSize) []byte {
	b.Helper()
	img := image.NewRGBA(image.Rect(0, 0, size.width, size.height))
	for y := 0; y < size.height; y++ {
		for x := 0; x < size.width; x++ {
			xGradient := x * 255 / size.width
			yGradient := y * 255 / size.height
			texture := (x*17 ^ y*31 ^ x/7 ^ y/11) & 0xff
			img.Set(x, y, color.RGBA{
				R: benchmarkBlendChannel(xGradient, texture, 3),
				G: benchmarkBlendChannel((xGradient+yGradient)/2, texture, 5),
				B: benchmarkBlendChannel(255-yGradient, texture, 4),
				A: 255,
			})
		}
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 85}); err != nil {
		b.Fatalf("encode benchmark jpeg: %v", err)
	}
	return out.Bytes()
}

func benchmarkBlendChannel(gradient int, texture int, divisor int) uint8 {
	return uint8((gradient + texture/divisor) % 256)
}
