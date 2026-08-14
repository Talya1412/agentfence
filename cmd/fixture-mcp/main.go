package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var msg message
		if json.Unmarshal(scanner.Bytes(), &msg) != nil {
			continue
		}
		var result interface{}
		switch msg.Method {
		case "tools/list":
			result = map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo", "description": "fixture", "inputSchema": map[string]string{"type": "object"}}, map[string]interface{}{"name": "blocked", "description": "fixture", "inputSchema": map[string]string{"type": "object"}}}}
		case "tools/call":
			var params struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(msg.Params, &params)
			result = map[string]interface{}{"content": []interface{}{map[string]string{"type": "text", "text": params.Name + " result"}}}
		default:
			result = map[string]string{"ok": "true"}
		}
		response := map[string]interface{}{"jsonrpc": "2.0", "id": json.RawMessage(msg.ID), "result": result}
		data, _ := json.Marshal(response)
		_, _ = fmt.Fprintln(os.Stdout, string(data))
	}
}
