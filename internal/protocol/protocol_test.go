package protocol

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestRead_rejectsTrailingJSON(t *testing.T) {
	_, err := Read(bufio.NewReader(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"x"} {}` + "\n")))
	if err == nil {
		t.Fatal("expected trailing JSON rejection")
	}
}

func TestRead_rejectsAmbiguousAndInvalidIDs(t *testing.T) {
	cases := []string{
		`{"jsonrpc":"2.0","id":null,"method":"x"}`,
		`{"jsonrpc":"2.0","id":{},"method":"x"}`,
		`{"jsonrpc":"2.0","id":1.5,"method":"x"}`,
		`{"jsonrpc":"2.0","id":1,"method":"x","result":{}}`,
	}
	for _, input := range cases {
		if _, err := Read(bufio.NewReader(strings.NewReader(input + "\n"))); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestRead_rejectsDuplicateObjectKeys(t *testing.T) {
	cases := []string{
		`{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"x"}`,
		`{"jsonrpc":"2.0","id":1,"method":"x","params":{"cursor":"one","cursor":"two"}}`,
	}
	for _, input := range cases {
		if _, err := Read(bufio.NewReader(strings.NewReader(input + "\n"))); err == nil {
			t.Fatalf("accepted duplicate key frame %s", input)
		}
	}
}

func TestRead_rejectsOversizedFrame(t *testing.T) {
	if _, err := ReadLimit(bufio.NewReader(strings.NewReader(`{"jsonrpc":"2.0","method":"x"}`+"\n")), 10); err == nil {
		t.Fatal("expected frame limit")
	}
}

func TestReadLimit_stopsUnterminatedFrameAtLimit(t *testing.T) {
	reader := &countingReader{data: strings.Repeat("x", 100)}
	_, err := ReadLimit(bufio.NewReaderSize(reader, 8), 16)
	if err == nil {
		t.Fatal("expected frame limit")
	}
	if reader.index > 32 {
		t.Fatalf("read %d bytes past frame limit", reader.index)
	}
}

type countingReader struct {
	data  string
	index int
	reads int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.reads++
	if r.index == len(r.data) {
		return 0, io.EOF
	}
	count := copy(p, r.data[r.index:])
	r.index += count
	return count, nil
}
