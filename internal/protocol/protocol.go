package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

const DefaultMaxFrameBytes = 1024 * 1024

type Kind uint8

const (
	Request Kind = iota + 1
	Notification
	ResponseKind
)

type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func Read(r *bufio.Reader) (Message, error) {
	return ReadLimit(r, DefaultMaxFrameBytes)
}

func ReadLimit(r *bufio.Reader, maxBytes int) (Message, error) {
	if maxBytes <= 0 {
		return Message{}, fmt.Errorf("invalid frame limit")
	}
	line := make([]byte, 0, min(maxBytes, 4096))
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxBytes {
			return Message{}, fmt.Errorf("JSON-RPC frame exceeds %d bytes", maxBytes)
		}
		if err == nil {
			break
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			if len(line) == 0 {
				return Message{}, io.EOF
			}
			return Message{}, fmt.Errorf("JSON-RPC frame must end with newline")
		}
		return Message{}, err
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Message{}, fmt.Errorf("empty JSON-RPC frame")
	}
	if err := rejectDuplicateKeys(line); err != nil {
		return Message{}, fmt.Errorf("invalid JSON-RPC line: %w", err)
	}
	var msg Message
	decoder := json.NewDecoder(bytes.NewReader(line))
	if err := decoder.Decode(&msg); err != nil {
		return Message{}, fmt.Errorf("invalid JSON-RPC line: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return Message{}, fmt.Errorf("trailing JSON-RPC data")
	}
	if msg.JSONRPC != "2.0" {
		return Message{}, fmt.Errorf("invalid JSON-RPC version")
	}
	kind, err := Classify(msg)
	if err != nil {
		return Message{}, err
	}
	if kind == Request || kind == Notification {
		if msg.Method == "" {
			return Message{}, fmt.Errorf("JSON-RPC request method is required")
		}
	}
	return msg, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON-RPC data")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			keys := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key must be string")
				}
				if _, exists := keys[key]; exists {
					return fmt.Errorf("duplicate object key %q", key)
				}
				keys[key] = struct{}{}
				if err := scanJSONValue(decoder); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := scanJSONValue(decoder); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
		_, err = decoder.Token()
		return err
	default:
		return nil
	}
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func Classify(msg Message) (Kind, error) {
	hasID := len(msg.ID) > 0
	if hasID && string(msg.ID) == "null" {
		return 0, fmt.Errorf("JSON-RPC id must not be null")
	}
	if hasID {
		var id interface{}
		decoder := json.NewDecoder(bytes.NewReader(msg.ID))
		decoder.UseNumber()
		if err := decoder.Decode(&id); err != nil {
			return 0, fmt.Errorf("invalid JSON-RPC id")
		}
		switch id.(type) {
		case string:
		case json.Number:
			if !isIntegerNumber(id.(json.Number).String()) {
				return 0, fmt.Errorf("JSON-RPC id must be string or integer")
			}
		default:
			return 0, fmt.Errorf("JSON-RPC id must be string or integer")
		}
	}
	hasMethod := msg.Method != ""
	hasResult := len(msg.Result) > 0
	hasError := len(msg.Error) > 0
	if hasMethod && (hasResult || hasError) {
		return 0, fmt.Errorf("ambiguous JSON-RPC message shape")
	}
	if hasResult && hasError {
		return 0, fmt.Errorf("response must contain result or error, not both")
	}
	if hasMethod {
		if hasID {
			return Request, nil
		}
		return Notification, nil
	}
	if hasID && (hasResult || hasError) {
		return ResponseKind, nil
	}
	return 0, fmt.Errorf("invalid JSON-RPC message shape")
}

func isIntegerNumber(value string) bool {
	rational, ok := new(big.Rat).SetString(value)
	return ok && rational.IsInt()
}
func Write(w io.Writer, msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", data)
	return err
}
func Response(id json.RawMessage, result interface{}) (Message, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return Message{}, fmt.Errorf("marshal JSON-RPC result: %w", err)
	}
	return Message{JSONRPC: "2.0", ID: id, Result: data}, nil
}
func ErrorResponse(id json.RawMessage, code int, message string, data interface{}) (Message, error) {
	payload := map[string]interface{}{"code": code, "message": message, "data": data}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Message{}, fmt.Errorf("marshal JSON-RPC error: %w", err)
	}
	return Message{JSONRPC: "2.0", ID: id, Error: encoded}, nil
}
