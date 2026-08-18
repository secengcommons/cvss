package metricvalue

const alphabetStart = 'A'

var strings = ['Z' - alphabetStart + 1]string{
	'A' - alphabetStart: "A", 'C' - alphabetStart: "C",
	'F' - alphabetStart: "F", 'H' - alphabetStart: "H",
	'L' - alphabetStart: "L", 'M' - alphabetStart: "M",
	'N' - alphabetStart: "N", 'O' - alphabetStart: "O",
	'P' - alphabetStart: "P", 'R' - alphabetStart: "R",
	'S' - alphabetStart: "S", 'T' - alphabetStart: "T",
	'U' - alphabetStart: "U", 'W' - alphabetStart: "W",
}

func String(value byte) string {
	if value >= 'A' && value <= 'Z' {
		return strings[value-alphabetStart]
	}
	return ""
}
