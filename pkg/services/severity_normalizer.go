package services

import "strings"

type SeverityNormalizer struct{}

func NewSeverityNormalizer() *SeverityNormalizer {
	return &SeverityNormalizer{}
}

func (sn *SeverityNormalizer) Normalize(baseScore *float64, enisaSeverity, bsiSeverity string) (float64, string) {
	if baseScore != nil && *baseScore > 0 {
		return *baseScore, scoreToSeverity(*baseScore)
	}

	if enisaSeverity != "" {
		return severityToScore(enisaSeverity), strings.ToLower(enisaSeverity)
	}

	if bsiSeverity != "" {
		mapped := mapBSISeverity(bsiSeverity)
		return severityToScore(mapped), mapped
	}

	return 0.0, "unknown"
}

func severityToScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 10.0
	case "high":
		return 8.0
	case "medium":
		return 5.0
	case "low":
		return 2.0
	default:
		return 0.0
	}
}

func mapBSISeverity(de string) string {
	switch de {
	case "kritisch":
		return "critical"
	case "hoch":
		return "high"
	case "mittel":
		return "medium"
	case "niedrig":
		return "low"
	default:
		return "unknown"
	}
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}
