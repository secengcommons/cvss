package vectorinput

import "encoding/json"

const (
	// MaxTextBytes is a fixed resource ceiling above every supported vector form
	MaxTextBytes = 256
	MaxJSONBytes = MaxTextBytes*len(`\u00ff`) + len(`""`)
)

func ValidText(text string) bool { return len(text) > 0 && len(text) <= MaxTextBytes }

func UnmarshalText[T any](target *T, text []byte, parse func(string) (T, error), invalid error) error {
	if target == nil || len(text) == 0 || len(text) > MaxTextBytes {
		return invalid
	}
	return replace(target, string(text), parse)
}

func UnmarshalJSON[T any](target *T, data []byte, parse func(string) (T, error), invalid error) error {
	if target == nil {
		return invalid
	}
	text, valid := jsonText(data)
	if !valid {
		return invalid
	}
	return replace(target, text, parse)
}

func replace[T any](target *T, text string, parse func(string) (T, error)) error {
	parsed, err := parse(text)
	if err != nil {
		return err
	}
	*target = parsed
	return nil
}

func jsonText(data []byte) (string, bool) {
	if len(data) == 0 || len(data) > MaxJSONBytes {
		return "", false
	}
	if text, ok := plain(data); ok {
		value := string(text)
		return value, ValidText(value)
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil || !ValidText(text) {
		return "", false
	}
	return text, true
}

func plain(data []byte) ([]byte, bool) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return nil, false
	}
	text := data[1 : len(data)-1]
	for _, value := range text {
		if value < 0x20 || value == '"' || value == '\\' {
			return nil, false
		}
	}
	return text, true
}
