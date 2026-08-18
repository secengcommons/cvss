package score

const maxTextBytes = len("10.0")

func AppendText(text []byte, tenths int) []byte {
	if tenths == 100 {
		return append(text, "10.0"...)
	}
	return append(text, "0123456789"[tenths/10], '.', "0123456789"[tenths%10])
}

func String(tenths int) string { return string(AppendText(make([]byte, 0, maxTextBytes), tenths)) }

func Severity(tenths int) string {
	switch {
	case tenths == 0:
		return "NONE"
	case tenths < 40:
		return "LOW"
	case tenths < 70:
		return "MEDIUM"
	case tenths < 90:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
