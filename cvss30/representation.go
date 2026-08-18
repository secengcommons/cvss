package cvss30

import "github.com/cticommons/cvss/internal/cvss3"

const baseStateCount = cvss3.BaseStateCount

type decodedVector = cvss3.Decoded

func (vector Vector) decode() decodedVector {
	return vector.state.Decode()
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
