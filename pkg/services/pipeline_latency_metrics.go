package services

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Pipeline latency metrics. These track the full vulnerability disclosure
// pipeline from CVE publication to operator notification.
var (
	pipelineFeedToMatch = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "pipeline_feed_to_match_seconds",
		Help:    "Time from feed ingestion to vulnerability matched against SBOM component.",
		Buckets: prometheus.ExponentialBuckets(1, 2, 15), // 1s to ~4.5h
	})

	pipelineMatchToSLA = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "pipeline_match_to_sla_seconds",
		Help:    "Time from vulnerability match to SLA deadline calculated.",
		Buckets: prometheus.ExponentialBuckets(0.5, 2, 12), // 0.5s to ~17m
	})

	pipelineSLAToAlert = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "pipeline_sla_to_alert_seconds",
		Help:    "Time from SLA calculation to operator alert sent.",
		Buckets: prometheus.ExponentialBuckets(0.5, 2, 12), // 0.5s to ~17m
	})

	pipelineFeedToReport = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "pipeline_feed_to_report_seconds",
		Help:    "End-to-end time from CVE feed ingestion to disclosure report filed.",
		Buckets: prometheus.ExponentialBuckets(1, 2, 18), // 1s to ~36h
	})

	pipelineSLAErosion = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "pipeline_sla_erosion_seconds",
		Help:    "How much SLA time is consumed by pipeline latency before operator sees the vulnerability.",
		Buckets: prometheus.ExponentialBuckets(1, 2, 18), // 1s to ~36h
	})

	pipelineSLAErosionPercent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pipeline_sla_erosion_percent",
		Help: "Percentage of SLA window consumed by pipeline latency, by severity.",
	}, []string{"severity"})
)

func init() {
	prometheus.MustRegister(
		pipelineFeedToMatch,
		pipelineMatchToSLA,
		pipelineSLAToAlert,
		pipelineFeedToReport,
		pipelineSLAErosion,
		pipelineSLAErosionPercent,
	)
}
