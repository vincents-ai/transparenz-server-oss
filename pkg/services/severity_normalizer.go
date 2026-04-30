package services

type SeverityNormalizer struct{}

func NewSeverityNormalizer() *SeverityNormalizer {
	return &SeverityNormalizer{}
}

func (sn *SeverityNormalizer) Normalize(baseScore *float64, enisaSeverity, bsiSeverity string) (float64, string) {
	if baseScore != nil && *baseScore > 0 {
		return *baseScore, scoreToSeverity(*baseScore)
	}

	if enisaSeverity != "" {
		return severityToScore(enisaSeverity), enisaSeverity
	}

	if bsiSeverity != "" {
		mapped := mapBSISeverity(bsiSeverity)
		return severityToScore(mapped), mapped
	}

	return 0.0, "unknown"
}

func severityToScore(severity string) float64 {
	switch severity {
	case "Critical":
		return 10.0
	case "High":
		return 8.0
	case "Medium":
		return 5.0
	case "Low":
		return 2.0
	default:
		return 0.0
	}
}

func mapBSISeverity(de string) string {
	switch de {
	case "kritisch":
		return "Critical"
	case "hoch":
		return "High"
	case "mittel":
		return "Medium"
	case "niedrig":
		return "Low"
	default:
		return "unknown"
	}
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "unknown"
	}
}
