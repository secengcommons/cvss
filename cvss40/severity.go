package cvss40

var highestEQ1 = [][][]int{
	{{0, 0, 0}},
	{{1, 0, 0}, {0, 1, 0}, {0, 0, 1}},
	{{3, 0, 0}, {1, 1, 1}},
}

var highestEQ2 = [][][]int{
	{{0, 0}},
	{{0, 1}, {1, 0}},
}

var highestEQ4 = [][][]int{
	{{0, -1, -1}},
	{{0, 0, 0}},
	{{1, 1, 1}},
}

var highestEQ3EQ6 = [][][][]int{
	{
		{{0, 0, 0, 0, 0, 0}},
		{{0, 0, 1, 1, 1, 0}, {0, 0, 0, 1, 1, 1}},
	},
	{
		{{1, 0, 0, 0, 0, 0}, {0, 1, 0, 0, 0, 0}},
		{{0, 1, 0, 1, 0, 1}, {0, 1, 1, 1, 0, 0}, {1, 0, 0, 0, 1, 1}, {1, 0, 1, 0, 1, 0}, {1, 1, 0, 0, 0, 1}},
	},
	{
		nil,
		{{1, 1, 1, 0, 0, 0}},
	},
}

func severityDistances(values [11]byte, eq macroVector) [5]float64 {
	const step = 0.1
	actual := []int{
		rank(values[0], "NALP"), rank(values[1], "LH"), rank(values[2], "NP"),
		rank(values[3], "NLH"), rank(values[4], "NPA"),
		rank(values[5], "HLN"), rank(values[6], "HLN"), rank(values[7], "HLN"),
		rank(values[8], "HLN"), rank(values[9], "HLN"), rank(values[10], "HLN"),
		0, 0, 0,
	}
	var distances [5]float64
	found := false
	for _, eq1 := range highestEQ1[eq[0]] {
		for _, eq2 := range highestEQ2[eq[1]] {
			for _, combined := range highestEQ3EQ6[eq[2]][eq[5]] {
				for _, eq4 := range highestEQ4[eq[3]] {
					candidate := []int{eq1[0], eq2[0], eq2[1], eq1[1], eq1[2], combined[0], combined[1], combined[2], eq4[0], eq4[1], eq4[2], combined[3], combined[4], combined[5]}
					if !dominates(actual, candidate) {
						continue
					}
					distances[0] = float64(actual[0]-candidate[0]+actual[3]-candidate[3]+actual[4]-candidate[4]) * step / (float64(depth(0, eq)+1) * step)
					distances[1] = float64(actual[1]-candidate[1]+actual[2]-candidate[2]) * step / (float64(depth(1, eq)+1) * step)
					distances[2] = float64(actual[5]-candidate[5]+actual[6]-candidate[6]+actual[7]-candidate[7]+actual[11]-candidate[11]+actual[12]-candidate[12]+actual[13]-candidate[13]) * step / (float64(depth(2, eq)+1) * step)
					distances[3] = float64(actual[8]-candidate[8]+actual[9]-candidate[9]+actual[10]-candidate[10]) * step / (float64(depth(3, eq)+1) * step)
					found = true
				}
			}
		}
	}
	if !found {
		panic("CVSS 4.0 Base vector has no highest-severity vector")
	}
	return distances
}

func rank(value byte, order string) int {
	for index := range len(order) {
		if order[index] == value {
			return index
		}
	}
	panic("invalid CVSS 4.0 metric value")
}

func dominates(actual, candidate []int) bool {
	for index := range actual {
		if candidate[index] < 0 || actual[index] < candidate[index] {
			return false
		}
	}
	return true
}

func depth(group int, eq macroVector) int {
	switch group {
	case 0:
		return [...]int{0, 3, 4}[eq[0]]
	case 1:
		return [...]int{0, 1}[eq[1]]
	case 2:
		if eq[2] == 0 {
			return [...]int{6, 5}[eq[5]]
		}
		if eq[2] == 1 {
			return 7
		}
		return 9
	case 3:
		return [...]int{5, 4, 3}[eq[3]]
	default:
		panic("invalid CVSS 4.0 equivalence group")
	}
}
