package keccak

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestSum256(t *testing.T) {
	for in, want := range map[string]string{
		"":    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
		// exactly one rate block, and more than one (js-sha3 0.9.3)
		strings.Repeat("a", 136): "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e",
		strings.Repeat("a", 200): "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d",
	} {
		got := Sum256([]byte(in))
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("keccak256(%q) = %x, want %s", in, got, want)
		}
	}
}

func TestSelector(t *testing.T) {
	for sig, want := range map[string]string{
		"transfer(address,uint256)": "0xa9059cbb",
		"balanceOf(address)":        "0x70a08231",
	} {
		if got := Selector(sig); got != want {
			t.Errorf("Selector(%s) = %s, want %s", sig, got, want)
		}
	}
}
