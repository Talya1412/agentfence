package proxy

import (
	"encoding/json"
	"testing"
)

func FuzzSchemaValidation_neverPanicsOnJSON(f *testing.F) {
	f.Add(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}`, `{"name":"agent"}`)
	f.Add(`{"type":"object","properties":{}}`, `{}`)
	f.Add(`{"type":"object","required":["missing"]}`, `{}`)

	f.Fuzz(func(t *testing.T, schemaJSON, argumentsJSON string) {
		var schema map[string]json.RawMessage
		if json.Unmarshal([]byte(schemaJSON), &schema) == nil {
			_ = validateSchema(schema)
			_ = argumentsMatchSchema(json.RawMessage(argumentsJSON), schema)
		}
	})
}
