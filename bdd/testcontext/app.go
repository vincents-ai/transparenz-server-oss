// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
package testcontext

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	apiPkg "github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/internal/api/rest"
	"github.com/transparenz/transparenz-server-oss/internal/config"
	"github.com/transparenz/transparenz-server-oss/pkg/interfaces"
	"github.com/transparenz/transparenz-server-oss/pkg/jobs"
	"github.com/transparenz/transparenz-server-oss/pkg/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"github.com/transparenz/transparenz-server-oss/pkg/services"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func BuildApp(ctx context.Context, db *gorm.DB, logger *zap.Logger) (*gin.Engine, *services.AlertHub, context.CancelFunc, error) {
	gin.SetMode(gin.TestMode)

	// Repositories
	scanRepo := repository.NewScanRepository(db)
	sbomRepo := repository.NewSbomRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	feedRepo := repository.NewVulnerabilityFeedRepository(db)
	slaRepo := repository.NewSlaTrackingRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	eventRepo := repository.NewComplianceEventRepository(db)
	subRepo := repository.NewEnisaSubmissionRepository(db)
	disclosureRepo := repository.NewVulnerabilityDisclosureRepository(db)
	vexStmtRepo := repository.NewVexStatementRepository(db)
	vexPubRepo := repository.NewVexPublicationRepository(db)
	grcRepo := repository.NewGRCMappingRepository(db)
	scanVulnRepo := repository.NewScanVulnerabilityRepository(db)

	// Jobs
	jobQueue := jobs.NewJobQueue(db, logger, 0)

	// Services (OSS only — no proprietary services)
	alertHub := services.NewAlertHub(logger)
	signingService := services.NewSigningService(db, logger, "")
	csafGenerator := services.NewCSAFGeneratorWithOrg(vulnRepo, feedRepo, slaRepo, orgRepo)
	enisaService := services.NewENISAService(orgRepo, subRepo, csafGenerator, nil, nil, 0, 0, 0)

	vulnzMatcher := services.NewVulnzMatcher(feedRepo, logger)
	scanWorker := services.NewScanWorker(scanRepo, vulnRepo, feedRepo, sbomRepo, jobQueue, logger, nil, scanVulnRepo)
	scanWorker.SetVulnzMatcher(vulnzMatcher)
	scanService := services.NewScanService(scanRepo, sbomRepo, scanWorker)

	vexService := services.NewVEXService(vexStmtRepo, vexPubRepo, feedRepo, vulnRepo, db, logger, csafGenerator, enisaService)
	disclosureService := services.NewDisclosureService(disclosureRepo)
	slaCalculator := services.NewSlaCalculator(vulnRepo, slaRepo, orgRepo, enisaService, db, logger, 0)

	// Handlers
	csafProviderHandler := rest.NewCSAFProviderHandler(subRepo, orgRepo, csafGenerator, logger, "http://localhost:8080")
	alertHandler := rest.NewAlertHandler(alertHub, testJWTSecret)
	enisaHandler := rest.NewENISAHandler(interfaces.ENISASubmitter(enisaService), subRepo, logger)
	scanHandler := rest.NewScanHandlerWithVulns(scanService, scanVulnRepo, logger)
	sbomHandler := rest.NewSbomHandler(sbomRepo, int64(10*1024*1024), alertHub)
	vulnHandler := rest.NewVulnerabilityHandler(vulnRepo, grcRepo)
	complianceHandler := rest.NewComplianceHandler(slaRepo, vulnRepo, eventRepo, orgRepo, grcRepo, logger)
	orgHandler := rest.NewOrganizationHandler(orgRepo, logger)
	disclosureHandler := rest.NewDisclosureHandler(disclosureService, logger)
	vexHandler := rest.NewVEXHandler(vexService, vexStmtRepo, logger)
	feedStatusHandler := rest.NewFeedStatusHandler(feedRepo)
	auditHandler := rest.NewAuditHandler(signingService)
	exportHandler := rest.NewExportHandler(eventRepo, orgRepo, sbomRepo, grcRepo)
	csafFeedHandler := rest.NewCSAFFeedIngestionHandler(feedRepo, logger)

	// Router
	router := gin.New()
	router.Use(middleware.RequestIDMiddleware())
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:8080"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type", "X-Request-ID"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	router.Use(rest.ErrorRecoveryMiddleware(logger))
	router.Use(config.LoggingMiddleware(logger))

	// Health
	router.GET("/health", func(c *gin.Context) {
		sqlDB, err := db.DB()
		if err != nil || sqlDB.PingContext(c.Request.Context()) != nil {
			c.Header("Content-Type", "application/problem+json")
			c.JSON(503, gin.H{"type": "about:blank", "title": "Service Unavailable", "status": 503, "detail": "database unreachable"})
			return
		}
		c.Header("Content-Type", "application/problem+json")
		c.JSON(200, gin.H{"type": "about:blank", "title": "OK", "status": 200, "detail": "service is healthy"})
	})

	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "service is ready"})
	})

	// CSAF v2.0 public provider endpoints (no auth — for aggregators)
	wellKnown := router.Group("/.well-known/csaf")
	{
		wellKnown.GET("/:org_slug/provider-metadata.json", csafProviderHandler.WellKnownProviderMetadata)
		wellKnown.GET("/:org_slug/changes.csv", csafProviderHandler.WellKnownChanges)
		wellKnown.GET("/:org_slug/:advisory_id.json", csafProviderHandler.WellKnownAdvisory)
	}

	// Authenticated API routes
	apiGroup := router.Group("/api")
	apiGroup.Use(middleware.JWTMiddleware(testJWTSecret))
	apiGroup.Use(middleware.TenantMiddleware())
	apiGroup.Use(middleware.ParseOrgIDMiddleware())
	{
		apiGroup.POST("/scan", scanHandler.CreateScan)
		apiGroup.GET("/scans", scanHandler.ListScans)
		apiGroup.GET("/scans/:id/vulnerabilities", scanHandler.GetScanVulnerabilities)

		apiGroup.POST("/sboms/upload", sbomHandler.Upload)
		apiGroup.GET("/sboms", sbomHandler.List)
		apiGroup.GET("/sboms/:id", sbomHandler.GetByID)
		apiGroup.GET("/sboms/:id/download", sbomHandler.Download)
		apiGroup.DELETE("/sboms/:id", sbomHandler.Delete)

		apiGroup.GET("/vulnerabilities", vulnHandler.ListVulnerabilities)
		apiGroup.GET("/vulnerabilities/:cve", vulnHandler.GetVulnerability)

		apiGroup.GET("/compliance/status", complianceHandler.GetComplianceStatus)
		apiGroup.GET("/compliance/sla", complianceHandler.ListSlaTracking)

		apiGroup.GET("/orgs/support-period", orgHandler.GetSupportPeriod)

		apiGroup.GET("/enisa/submissions", enisaHandler.ListSubmissions)
		apiGroup.GET("/enisa/submissions/:id", enisaHandler.GetSubmission)
		apiGroup.GET("/enisa/submissions/:id/download", enisaHandler.DownloadSubmission)
		// ENISA submit stub: returns 403 in OSS
		apiGroup.POST("/enisa/submit", func(c *gin.Context) {
			apiPkg.Forbidden(c, "ENISA submission requires the commercial edition of transparenz-server")
		})

		apiGroup.GET("/alerts/stream", alertHandler.StreamAlerts)

		apiGroup.POST("/disclosures", disclosureHandler.CreateDisclosure)
		apiGroup.GET("/disclosures", disclosureHandler.ListDisclosures)
		apiGroup.GET("/disclosures/sla-compliance", disclosureHandler.CheckSLACompliance)
		apiGroup.GET("/disclosures/:id", disclosureHandler.GetDisclosure)
		apiGroup.PUT("/disclosures/:id/status", disclosureHandler.UpdateStatus)

		apiGroup.GET("/feeds/status", feedStatusHandler.GetStatus)

		apiGroup.GET("/csaf/provider-metadata.json", csafProviderHandler.GetProviderMetadata)
		apiGroup.GET("/csaf/advisories", csafProviderHandler.ListAdvisories)
		apiGroup.GET("/csaf/advisories/:id", csafProviderHandler.GetAdvisory)
		apiGroup.GET("/csaf/changes.csv", csafProviderHandler.GetChanges)

		apiGroup.POST("/vex", vexHandler.CreateVEX)
		apiGroup.GET("/vex", vexHandler.ListVEX)

		apiGroup.GET("/audit/verify", auditHandler.VerifyAuditChain)
	}

	// Admin routes
	admin := apiGroup.Group("/")
	admin.Use(middleware.RequireRole("admin"))
	{
		admin.PUT("/orgs/support-period", orgHandler.UpdateSupportPeriod)
		admin.POST("/csaf/feeds/ingest", csafFeedHandler.IngestFeed)
	}

	// Compliance officer routes
	complianceGroup := apiGroup.Group("/")
	complianceGroup.Use(middleware.RequireRole("admin", "compliance_officer"))
	{
		complianceGroup.POST("/compliance/exploited", complianceHandler.ReportExploitedVulnerability)
		complianceGroup.GET("/export/audit", exportHandler.ExportAudit)
		complianceGroup.GET("/export/enriched-sbom/:sbom_id", exportHandler.ExportEnrichedSBOM)
		complianceGroup.POST("/vex/:id/approve", vexHandler.ApproveVEX)
		complianceGroup.POST("/vex/:id/publish", vexHandler.PublishVEX)
	}

	// Start background workers
	workersCtx, cancel := context.WithCancel(ctx)
	go scanWorker.Start(workersCtx)
	go slaCalculator.Start(workersCtx)

	return router, alertHub, cancel, nil
}

// Ensure imports used
var _ = http.MethodGet
