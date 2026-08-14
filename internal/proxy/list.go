package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/agentfence/agentfence/internal/protocol"
)

func (p Proxy) list(msg protocol.Message, kind protocol.Kind, out io.Writer, serverIn *bufio.Reader, downstream io.ReadWriter, schemas map[string]json.RawMessage) error {
	if kind == protocol.Notification {
		return protocol.Write(downstream, msg)
	}
	for name := range schemas {
		delete(schemas, name)
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
	allTools := tools
	seenCursors := map[string]bool{}
	listBytes := len(response.Result)
	for page := 1; ; page++ {
		cursor, hasCursor, cursorErr := nextCursor(payload)
		if cursorErr != nil {
			return cursorErr
		}
		if !hasCursor {
			break
		}
		if page >= p.listPageLimit() {
			return fmt.Errorf("tools/list pagination exceeds page limit")
		}
		if seenCursors[cursor] {
			return fmt.Errorf("tools/list pagination cursor cycle")
		}
		seenCursors[cursor] = true
		pageRequest, requestErr := listPageRequest(msg, cursor, page+1)
		if requestErr != nil {
			return requestErr
		}
		if err := protocol.Write(downstream, pageRequest); err != nil {
			return err
		}
		pageResponse, readErr := p.readResponse(pageRequest.ID, out, serverIn)
		if readErr != nil {
			return readErr
		}
		listBytes += len(pageResponse.Result)
		if listBytes > p.listByteLimit() {
			return fmt.Errorf("tools/list aggregate exceeds byte budget")
		}
		var pagePayload map[string]json.RawMessage
		if err := json.Unmarshal(pageResponse.Result, &pagePayload); err != nil {
			return fmt.Errorf("decode tools/list response: %w", err)
		}
		var pageTools []map[string]json.RawMessage
		if err := json.Unmarshal(pagePayload["tools"], &pageTools); err != nil {
			return fmt.Errorf("decode tools/list response: %w", err)
		}
		allTools = append(allTools, pageTools...)
		payload = pagePayload
	}
	filtered := make([]map[string]json.RawMessage, 0, len(allTools))
	for _, tool := range allTools {
		name, err := toolMetadata(tool)
		if err != nil {
			return err
		}
		if _, exists := schemas[name]; exists {
			return fmt.Errorf("tools/list response contains duplicate tool %q", name)
		}
		schemas[name] = tool["inputSchema"]
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

func toolMetadata(tool map[string]json.RawMessage) (string, error) {
	var name string
	if err := json.Unmarshal(tool["name"], &name); err != nil || name == "" {
		return "", fmt.Errorf("tools/list response contains tool without string name")
	}
	var inputSchema map[string]json.RawMessage
	if err := json.Unmarshal(tool["inputSchema"], &inputSchema); err != nil || inputSchema == nil {
		return "", fmt.Errorf("tools/list response contains tool without object inputSchema")
	}
	if err := validateSchema(inputSchema); err != nil {
		return "", fmt.Errorf("tools/list response contains invalid inputSchema: %w", err)
	}
	return name, nil
}

func toolBytes(tool map[string]json.RawMessage) []byte { data, _ := json.Marshal(tool); return data }

func (p Proxy) listPageLimit() int {
	if p.Config.Budgets.MaxListPages > 0 {
		return p.Config.Budgets.MaxListPages
	}
	return 32
}

func (p Proxy) listByteLimit() int {
	if p.Config.Budgets.MaxListBytes > 0 {
		return p.Config.Budgets.MaxListBytes
	}
	return p.frameLimit()
}

func nextCursor(payload map[string]json.RawMessage) (string, bool, error) {
	raw, ok := payload["nextCursor"]
	if !ok || string(raw) == "null" {
		return "", false, nil
	}
	var cursor string
	if json.Unmarshal(raw, &cursor) != nil || strings.TrimSpace(cursor) == "" {
		return "", false, fmt.Errorf("tools/list response contains malformed nextCursor")
	}
	return cursor, true, nil
}

func listPageRequest(original protocol.Message, cursor string, page int) (protocol.Message, error) {
	params := map[string]json.RawMessage{}
	if len(original.Params) > 0 && string(original.Params) != "null" {
		if err := json.Unmarshal(original.Params, &params); err != nil {
			return protocol.Message{}, fmt.Errorf("decode tools/list params: %w", err)
		}
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return protocol.Message{}, err
	}
	params["cursor"] = encoded
	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return protocol.Message{}, err
	}
	return protocol.Message{JSONRPC: "2.0", ID: json.RawMessage(strconv.Quote("agentfence-list-" + strconv.Itoa(page))), Method: original.Method, Params: paramsBytes}, nil
}
