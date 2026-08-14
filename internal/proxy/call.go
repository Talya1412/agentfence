package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/agentfence/agentfence/internal/audit"
	"github.com/agentfence/agentfence/internal/policy"
	"github.com/agentfence/agentfence/internal/protocol"
)

func (p Proxy) call(msg protocol.Message, kind protocol.Kind, out io.Writer, serverIn *bufio.Reader, downstream io.ReadWriter, schemas map[string]json.RawMessage) error {
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
	if schema, ok := schemas[params.Name]; ok {
		var schemaObject map[string]json.RawMessage
		if json.Unmarshal(schema, &schemaObject) != nil || !argumentsMatchSchema(params.Arguments, schemaObject) {
			if kind == protocol.Notification {
				return nil
			}
			response, responseErr := protocol.ErrorResponse(msg.ID, -32602, "invalid params", "schema_validation_failed")
			if responseErr != nil {
				return responseErr
			}
			return p.writeBounded(out, response)
		}
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
