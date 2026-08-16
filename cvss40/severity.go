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
	{{0, 0, 0}},
	{{0, 1, 1}},
	{{1, 2, 2}},
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

func severityDistances(values scoringValues, eq macroVector) [5]float64 {
	actual := []int{
		rank(values.metrics[0], "NALP"), rank(values.metrics[1], "LH"), rank(values.metrics[2], "NP"),
		rank(values.metrics[3], "NLH"), rank(values.metrics[4], "NPA"),
		rank(values.metrics[5], "HLN"), rank(values.metrics[6], "HLN"), rank(values.metrics[7], "HLN"),
		rank(values.metrics[8], "HLN"), rank(values.metrics[9], "SHLN"), rank(values.metrics[10], "SHLN"),
		rank(values.requirements[0], "HML"), rank(values.requirements[1], "HML"), rank(values.requirements[2], "HML"),
	}
	var distances [5]float64
	for _, eq1 := range highestEQ1[eq[0]] {
		for _, eq2 := range highestEQ2[eq[1]] {
			for _, combined := range highestEQ3EQ6[eq[2]][eq[5]] {
				for _, eq4 := range highestEQ4[eq[3]] {
					candidate := []int{eq1[0], eq2[0], eq2[1], eq1[1], eq1[2], combined[0], combined[1], combined[2], eq4[0], eq4[1], eq4[2], combined[3], combined[4], combined[5]}
					if !dominates(actual, candidate) {
						continue
					}
					distances[0] = severityProportion(actual, candidate, depth(0, eq), 0, 3, 4)
					distances[1] = severityProportion(actual, candidate, depth(1, eq), 1, 2)
					distances[2] = severityProportion(actual, candidate, depth(2, eq), 5, 6, 7, 11, 12, 13)
					distances[3] = severityProportion(actual, candidate, depth(3, eq), 8, 9, 10)
					return distances
				}
			}
		}
	}
	panic("CVSS 4.0 vector has no highest-severity vector")
}

func severityProportion(actual, candidate []int, groupDepth int, indices ...int) float64 {
	const step = 0.1
	distance := 0.0
	for _, index := range indices {
		distance += float64(actual[index]-candidate[index]) * step
	}
	return distance / (float64(groupDepth+1) * step)
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
