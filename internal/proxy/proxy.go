package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/agentfence/agentfence/internal/audit"
	"github.com/agentfence/agentfence/internal/config"
	"github.com/agentfence/agentfence/internal/policy"
	"github.com/agentfence/agentfence/internal/protocol"
)

type Proxy struct {
	Config   config.Config
	Audit    io.Writer
	Redactor audit.Redactor
}

func (p Proxy) Run(client io.Reader, clientOut io.Writer, downstream io.ReadWriter) error {
	in, serverIn := bufio.NewReader(client), bufio.NewReader(downstream)
	for {
		msg, err := protocol.ReadLimit(in, p.frameLimit())
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		kind, err := protocol.Classify(msg)
		if err != nil {
			return err
		}
		switch msg.Method {
		case "tools/list":
			if err := p.list(msg, kind, clientOut, serverIn, downstream); err != nil {
				return err
			}
		case "tools/call":
			if err := p.call(msg, kind, clientOut, serverIn, downstream); err != nil {
				return err
			}
		default:
			if err := p.forward(msg, kind, clientOut, serverIn, downstream); err != nil {
				return err
			}
		}
	}
}

func (p Proxy) frameLimit() int {
	if p.Config.Budgets.MaxFrameBytes > 0 {
		return p.Config.Budgets.MaxFrameBytes
	}
	return protocol.DefaultMaxFrameBytes
}

func (p Proxy) list(msg protocol.Message, kind protocol.Kind, out io.Writer, serverIn *bufio.Reader, downstream io.ReadWriter) error {
	if kind == protocol.Notification {
		return protocol.Write(downstream, msg)
	}
	if err := protocol.Write(downstream, msg); err != nil {
		return err
	}
	response, err := p.readResponse(msg.ID, out, serverIn)
	if err != nil {
		return err
	}
	if len(response.Result) == 0 {
		return fmt.Errorf("tools/list response missing result")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(response.Result, &payload); err != nil {
		return fmt.Errorf("decode tools/list response: %w", err)
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(payload["tools"], &tools); err != nil {
		return fmt.Errorf("decode tools/list response: %w", err)
	}
	filtered := make([]map[string]json.RawMessage, 0, len(tools))
	for _, tool := range tools {
		var name string
		if err := json.Unmarshal(tool["name"], &name); err != nil || name == "" {
			return fmt.Errorf("tools/list response contains tool without string name")
		}
		var inputSchema map[string]json.RawMessage
		if err := json.Unmarshal(tool["inputSchema"], &inputSchema); err != nil || inputSchema == nil {
			return fmt.Errorf("tools/list response contains tool without object inputSchema")
		}
		policyTool, explicit := p.Config.Tools[name]
		if (explicit && policyTool.Decision != "allow") || (!explicit && p.Config.Defaults.Decision != "allow") {
			continue
		}
		value := map[string]interface{}{}
		if err := json.Unmarshal(toolBytes(tool), &value); err != nil {
			return err
		}
		redacted, err := p.redactValue(value)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(redacted)
		if err != nil {
			return err
		}
		var preserved map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &preserved); err != nil {
			return err
		}
		filtered = append(filtered, preserved)
	}
	if cursor, ok := payload["nextCursor"]; ok && string(cursor) != "null" && string(cursor) != `""` {
		return fmt.Errorf("tools/list pagination is unsupported: downstream returned nextCursor")
	}
	payload["tools"], err = json.Marshal(filtered)
	if err != nil {
		return err
	}
	response.Result, err = json.Marshal(payload)
	if err != nil {
		return err
	}
	return p.writeBounded(out, response)
}

func toolBytes(tool map[string]json.RawMessage) []byte { data, _ := json.Marshal(tool); return data }

func (p Proxy) call(msg protocol.Message, kind protocol.Kind, out io.Writer, serverIn *bufio.Reader, downstream io.ReadWriter) error {
	params, err := validCallParams(msg.Params)
	if err != nil {
		if kind == protocol.Notification {
			return nil
		}
		response, responseErr := protocol.ErrorResponse(msg.ID, -32602, "invalid params", "invalid_params")
		if responseErr != nil {
			return responseErr
		}
		return p.writeBounded(out, response)
	}
	decision := policy.Evaluate(p.Config, policy.Request{Name: params.Name, Arguments: params.Arguments})
	if err := p.writeAudit(audit.Entry{Event: "tool_call", Method: msg.Method, Tool: params.Name, Decision: string(decision.Decision), Reason: decision.ReasonCode}); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	if decision.Decision != policy.Allow || p.Config.Mode == "dry-run" {
		if kind == protocol.Notification {
			return nil
		}
		response, err := protocol.ErrorResponse(msg.ID, -32001, decision.Explanation, decision.ReasonCode)
		if err != nil {
			return err
		}
		return p.writeBounded(out, response)
	}
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

type callParams struct {
	Name      string
	Arguments json.RawMessage
}

func validCallParams(raw json.RawMessage) (callParams, error) {
	var object map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &object) != nil {
		return callParams{}, fmt.Errorf("params must be object")
	}
	var name string
	if json.Unmarshal(object["name"], &name) != nil || strings.TrimSpace(name) == "" {
		return callParams{}, fmt.Errorf("name must be nonempty string")
	}
	arguments := object["arguments"]
	if len(arguments) == 0 {
		return callParams{}, fmt.Errorf("arguments must be object")
	}
	var args map[string]interface{}
	if json.Unmarshal(arguments, &args) != nil || args == nil {
		return callParams{}, fmt.Errorf("arguments must be object")
	}
	return callParams{Name: name, Arguments: arguments}, nil
}

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
func Inspect(cfg config.Config) string {
	return fmt.Sprintf("mode=%s default=%s tools=%d", cfg.Mode, cfg.Defaults.Decision, len(cfg.Tools))
}
