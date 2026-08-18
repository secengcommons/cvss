package cvss30

import "github.com/cticommons/cvss/internal/cvss3"

const baseStateCount = cvss3.BaseStateCount

type decodedVector struct {
	values   [cvss3.BaseMetricCount]byte
	optional [cvss3.OptionalMetricCount]byte
}

func (vector Vector) decode() decodedVector {
	decoded := vector.state.Decode()
	return decodedVector{values: decoded.Values, optional: decoded.Optional}
}

func (vector Vector) baseTenths() int { return int(baseScores[vector.state.Raw()%baseStateCount]) }

var baseScores = func() [baseStateCount]uint8 {
	var scores [baseStateCount]uint8
	for raw := range scores {
		state := cvss3.BaseState(uint64(raw))
		scores[raw] = scoreByte(baseScore(state.Decode().Values))
	}
	return scores
}()
