package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

func validateSchema(schema map[string]json.RawMessage) error {
	if schema == nil {
		return fmt.Errorf("schema must be object")
	}
	raw, ok := schema["type"]
	if !ok {
		return fmt.Errorf("schema type must be object")
	}
	var schemaType string
	if json.Unmarshal(raw, &schemaType) != nil || schemaType != "object" {
		return fmt.Errorf("schema type must be object")
	}
	if raw, ok := schema["required"]; ok {
		var required []string
		if json.Unmarshal(raw, &required) != nil {
			return fmt.Errorf("required must be string array")
		}
		var properties map[string]json.RawMessage
		if propertyRaw, exists := schema["properties"]; !exists || json.Unmarshal(propertyRaw, &properties) != nil {
			return fmt.Errorf("required needs properties object")
		}
		for _, name := range required {
			if _, exists := properties[name]; !exists {
				return fmt.Errorf("required property %q is undefined", name)
			}
		}
	}
	if raw, ok := schema["additionalProperties"]; ok {
		var allowed bool
		if json.Unmarshal(raw, &allowed) != nil || allowed {
			return fmt.Errorf("additionalProperties must be false")
		}
	}
	if raw, ok := schema["properties"]; ok {
		var properties map[string]json.RawMessage
		if json.Unmarshal(raw, &properties) != nil || properties == nil {
			return fmt.Errorf("properties must be object")
		}
		for name, property := range properties {
			var child map[string]json.RawMessage
			if json.Unmarshal(property, &child) != nil {
				return fmt.Errorf("property %q must be object", name)
			}
			if err := validatePropertySchema(child); err != nil {
				return fmt.Errorf("property %q: %w", name, err)
			}
		}
	}
	return nil
}

func validatePropertySchema(schema map[string]json.RawMessage) error {
	raw, ok := schema["type"]
	if !ok {
		return fmt.Errorf("type is required")
	}
	var schemaType string
	if json.Unmarshal(raw, &schemaType) != nil {
		return fmt.Errorf("type must be string")
	}
	switch schemaType {
	case "string", "number", "integer", "boolean", "null", "object", "array":
	default:
		return fmt.Errorf("unsupported type %q", schemaType)
	}
	if schemaType == "object" {
		return validateSchema(schema)
	}
	return nil
}

func argumentsMatchSchema(arguments json.RawMessage, schema map[string]json.RawMessage) bool {
	var value map[string]json.RawMessage
	if json.Unmarshal(arguments, &value) != nil || value == nil {
		return false
	}
	var required []string
	if raw, ok := schema["required"]; ok && json.Unmarshal(raw, &required) != nil {
		return false
	}
	for _, name := range required {
		if _, ok := value[name]; !ok {
			return false
		}
	}
	var properties map[string]json.RawMessage
	if raw, ok := schema["properties"]; ok && (json.Unmarshal(raw, &properties) != nil || properties == nil) {
		return false
	}
	if raw, ok := schema["additionalProperties"]; ok {
		var additional bool
		if json.Unmarshal(raw, &additional) != nil {
			return false
		}
		if !additional {
			for name := range value {
				if _, ok := properties[name]; !ok {
					return false
				}
			}
		}
	}
	for name, raw := range value {
		property, ok := properties[name]
		if !ok {
			continue
		}
		var propertySchema map[string]json.RawMessage
		if json.Unmarshal(property, &propertySchema) != nil || !valueMatchesType(raw, propertySchema) {
			return false
		}
	}
	return true
}

func valueMatchesType(raw json.RawMessage, schema map[string]json.RawMessage) bool {
	typeRaw, ok := schema["type"]
	if !ok {
		return false
	}
	var schemaType string
	if json.Unmarshal(typeRaw, &schemaType) != nil {
		return false
	}
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return false
	}
	switch schemaType {
	case "string":
		_, ok = value.(string)
	case "number":
		_, ok = value.(json.Number)
	case "integer":
		number, numberOK := value.(json.Number)
		ok = numberOK && isInteger(number.String())
	case "boolean":
		_, ok = value.(bool)
	case "null":
		ok = value == nil
	case "object":
		object, objectOK := value.(map[string]interface{})
		ok = objectOK && object != nil
	case "array":
		_, ok = value.([]interface{})
	default:
		ok = false
	}
	return ok
}

func isInteger(value string) bool { return !strings.ContainsAny(value, ".eE") }
