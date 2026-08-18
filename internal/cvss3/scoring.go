package cvss3

const (
	attackVectorIndex               = 0
	attackComplexityIndex           = 1
	privilegesIndex                 = 2
	userInteractionIndex            = 3
	ScopeIndex                      = 4
	TemporalMetricCount             = 3
	confidentialityIndex            = 5
	integrityIndex                  = 6
	availabilityIndex               = 7
	confidentialityRequirementIndex = 3
	integrityRequirementIndex       = 4
	availabilityRequirementIndex    = 5
	modifiedMetricStart             = 6
)

func Impact(metrics [BaseMetricCount]byte) float64 {
	iss := 1 - (1-impactWeight(metrics[confidentialityIndex]))*(1-impactWeight(metrics[integrityIndex]))*(1-impactWeight(metrics[availabilityIndex]))
	if metrics[ScopeIndex] == 'C' {
		return 7.52*(iss-.029) - 3.25*pow15(iss-.02)
	}
	return 6.42 * iss
}

func Exploitability(metrics [BaseMetricCount]byte) float64 {
	av := attackVectorWeight(metrics[attackVectorIndex])
	ac := attackComplexityWeight(metrics[attackComplexityIndex])
	pr := privilegesWeight(metrics[privilegesIndex], metrics[ScopeIndex])
	ui := userInteractionWeight(metrics[userInteractionIndex])
	return 8.22 * av * ac * pr * ui
}

func ModifiedImpact30(metrics [BaseMetricCount]byte, optional [OptionalMetricCount]byte) float64 {
	return modifiedImpact(metrics, optional, false)
}

func ModifiedImpact31(metrics [BaseMetricCount]byte, optional [OptionalMetricCount]byte) float64 {
	return modifiedImpact(metrics, optional, true)
}

func modifiedImpact(metrics [BaseMetricCount]byte, optional [OptionalMetricCount]byte, version31 bool) float64 {
	confidentiality := requirementWeight(optional[confidentialityRequirementIndex]) * impactWeight(metrics[confidentialityIndex])
	integrity := requirementWeight(optional[integrityRequirementIndex]) * impactWeight(metrics[integrityIndex])
	availability := requirementWeight(optional[availabilityRequirementIndex]) * impactWeight(metrics[availabilityIndex])
	miss := Clamp(1-(1-confidentiality)*(1-integrity)*(1-availability), .915)
	if metrics[ScopeIndex] != 'C' {
		return 6.42 * miss
	}
	if version31 {
		return 7.52*(miss-.029) - 3.25*pow13(miss*.9731-.02)
	}
	return 7.52*(miss-.029) - 3.25*pow15(miss-.02)
}

func TemporalWeight(optional [OptionalMetricCount]byte) float64 {
	return exploitCodeWeight(optional[0]) * remediationWeight(optional[1]) * confidenceWeight(optional[2])
}

func ModifiedMetrics(decoded Decoded) [BaseMetricCount]byte {
	metrics := decoded.Values
	for index := range BaseMetricCount {
		value := decoded.Optional[index+modifiedMetricStart]
		if value != 0 && value != UndefinedValue {
			metrics[index] = value
		}
	}
	return metrics
}

func EnvironmentalScore30(state State) int { return environmentalScore(state.Decode(), false) }

func EnvironmentalScore31(state State) int { return environmentalScore(state.Decode(), true) }

func EnvironmentalScoreDecoded30(decoded Decoded) int { return environmentalScore(decoded, false) }

func EnvironmentalScoreDecoded31(decoded Decoded) int { return environmentalScore(decoded, true) }

func environmentalScore(decoded Decoded, version31 bool) int {
	metrics := ModifiedMetrics(decoded)
	impact := modifiedImpact(metrics, decoded.Optional, version31)
	if impact <= 0 {
		return 0
	}
	raw := impact + Exploitability(metrics)
	if metrics[ScopeIndex] == 'C' {
		raw *= 1.08
	}
	modifiedBase := float64(roundup(Clamp(raw, 10), version31)) / 10
	return roundup(modifiedBase*TemporalWeight(decoded.Optional), version31)
}

func Roundup30(value float64) int { return roundup(value, false) }

func Roundup31(value float64) int { return roundup(value, true) }

func roundup(value float64, version31 bool) int {
	if version31 {
		return (int(value*100000+.5) + 9999) / 10000
	}
	scaled := value * 10
	result := int(scaled)
	if scaled > float64(result) {
		result++
	}
	return result
}

func pow13(value float64) float64 {
	squared := value * value
	fourth := squared * squared
	eighth := fourth * fourth
	return eighth * fourth * value
}

func pow15(value float64) float64 {
	squared := value * value
	fourth := squared * squared
	eighth := fourth * fourth
	return eighth * fourth * squared * value
}

func Clamp(value, maximum float64) float64 {
	if value > maximum {
		return maximum
	}
	return value
}

func attackVectorWeight(value byte) float64 {
	switch value {
	case 'N':
		return .85
	case 'A':
		return .62
	case 'L':
		return .55
	default:
		return .2
	}
}

func attackComplexityWeight(value byte) float64 {
	if value == 'L' {
		return .77
	}
	return .44
}

func userInteractionWeight(value byte) float64 {
	if value == 'N' {
		return .85
	}
	return .62
}

func privilegesWeight(value, scope byte) float64 {
	if value == 'N' {
		return .85
	}
	if scope == 'C' {
		if value == 'L' {
			return .68
		}
		return .5
	}
	if value == 'L' {
		return .62
	}
	return .27
}

func impactWeight(value byte) float64 {
	switch value {
	case 'H':
		return .56
	case 'L':
		return .22
	default:
		return 0
	}
}

func requirementWeight(value byte) float64 {
	switch value {
	case 'H':
		return 1.5
	case 'L':
		return .5
	default:
		return 1
	}
}

func exploitCodeWeight(value byte) float64 {
	switch value {
	case 'U':
		return .91
	case 'P':
		return .94
	case 'F':
		return .97
	default:
		return 1
	}
}

func remediationWeight(value byte) float64 {
	switch value {
	case 'O':
		return .95
	case 'T':
		return .96
	case 'W':
		return .97
	default:
		return 1
	}
}

func confidenceWeight(value byte) float64 {
	switch value {
	case 'U':
		return .92
	case 'R':
		return .96
	default:
		return 1
	}
}
