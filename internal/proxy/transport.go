package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/agentfence/agentfence/internal/audit"
	"github.com/agentfence/agentfence/internal/protocol"
)

func (p Proxy) forward(msg protocol.Message, kind protocol.Kind, out io.Writer, serverIn *bufio.Reader, downstream io.ReadWriter) error {
	if err := protocol.Write(downstream, msg); err != nil {
		return err
	}
	if kind == protocol.Notification {
		return nil
	}
	response, err := p.readResponse(msg.ID, out, serverIn)
	if err != nil {
		return err
	}
	return p.writeBounded(out, response)
}

func (p Proxy) readResponse(id json.RawMessage, out io.Writer, serverIn *bufio.Reader) (protocol.Message, error) {
	for {
		response, err := protocol.ReadLimit(serverIn, p.frameLimit())
		if err != nil {
			return protocol.Message{}, err
		}
		kind, err := protocol.Classify(response)
		if err != nil {
			return protocol.Message{}, err
		}
		if kind == protocol.Notification {
			redacted, redactionErr := p.redactMessage(response)
			if redactionErr != nil {
				return protocol.Message{}, redactionErr
			}
			if writeErr := p.writeBounded(out, redacted); writeErr != nil {
				return protocol.Message{}, writeErr
			}
			continue
		}
		if !bytes.Equal(response.ID, id) {
			return protocol.Message{}, fmt.Errorf("downstream response id does not match request")
		}
		redacted, err := p.redactMessage(response)
		if err != nil {
			return protocol.Message{}, err
		}
		return redacted, nil
	}
}

func (p Proxy) writeBounded(out io.Writer, msg protocol.Message) error {
	if len(msg.Result) > p.Config.Budgets.MaxResultBytes {
		return fmt.Errorf("result exceeds configured byte budget")
	}
	if len(msg.Error) > p.Config.Budgets.MaxResultBytes {
		return fmt.Errorf("error exceeds configured byte budget")
	}
	if countLines(msg.Result)+countLines(msg.Error) > p.Config.Budgets.MaxLines {
		return fmt.Errorf("response exceeds configured line budget")
	}
	return protocol.Write(out, msg)
}

func countLines(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	return bytes.Count(raw, []byte{'\n'}) + 1
}

func (p Proxy) redactMessage(msg protocol.Message) (protocol.Message, error) {
	for _, field := range []*json.RawMessage{&msg.Result, &msg.Error} {
		if len(*field) == 0 {
			continue
		}
		var value interface{}
		if err := json.Unmarshal(*field, &value); err != nil {
			return protocol.Message{}, err
		}
		redacted, err := p.redactValue(value)
		if err != nil {
			return protocol.Message{}, err
		}
		encoded, err := json.Marshal(redacted)
		if err != nil {
			return protocol.Message{}, err
		}
		*field = encoded
	}
	return msg, nil
}

func (p Proxy) redactValue(value interface{}) (interface{}, error) {
	redacted := p.Redactor.Apply(value)
	return redacted, nil
}

func (p Proxy) writeAudit(entry audit.Entry) error {
	if p.Audit == nil {
		return nil
	}
	line, err := audit.JSONLine(entry)
	if err != nil {
		return err
	}
	_, err = p.Audit.Write(line)
	return err
}
