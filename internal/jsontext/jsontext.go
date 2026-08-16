package jsontext

func Plain(data []byte) ([]byte, bool) {
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
