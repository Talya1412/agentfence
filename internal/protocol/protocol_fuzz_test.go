package protocol

import (
	"bufio"
	"strings"
	"testing"
)

func FuzzRead_neverPanicsOnProtocolInput(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}` + "\n")
	f.Add(`{"jsonrpc":"2.0","id":null,"method":"x"}` + "\n")
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"x","method":"y"}` + "\n")

	f.Fuzz(func(t *testing.T, input string) {
		_, _ = Read(bufio.NewReader(strings.NewReader(input)))
	})
}
