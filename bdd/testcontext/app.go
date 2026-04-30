// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package testcontext

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/internal/api/rest"
	"github.com/transparenz/transparenz-server-oss/internal/config"
	"github.com/transparenz/transparenz-server-oss/internal/jobs"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/repository"
	"github.com/transparenz/transparenz-server-oss/internal/services"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

const testJWTSecret = "bdd-test-secret-key-must-be-at-least-32-bytes!!"
const testEncryptionKey = "bdd-test-encryption-key-32bytes!"

type pdfAdapter struct {
	pdfService *services.PDFService
}

func (a *pdfAdapter) GeneratePDF(data models.PDFReportData) ([]byte, error) {
	return a.pdfService.GeneratePDF(data)
}

func BuildApp(ctx context.Context, db *gorm.DB, logger *zap.Logger) (*gin.Engine, *services.AlertHub, context.CancelFunc, error) {
	gin.SetMode(gin.TestMode)

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
	greenboneRepo := repository.NewGreenboneRepository(db)
	sbomWebhookRepo := repository.NewSbomWebhookRepository(db)
	telemetryRepo := repository.NewTelemetryRepository(db)
	grcRepo := repository.NewGRCMappingRepository(db)

	scanVulnRepo := repository.NewScanVulnerabilityRepository(db)

	jobQueue := jobs.NewJobQueue(db, logger, 0)

	vunnelSync := services.NewVulnzSyncService(feedRepo, services.NewRealVulnzFeedSource(), 6*time.Hour, logger)

	scanWorker := services.NewScanWorker(scanRepo, vulnRepo, feedRepo, sbomRepo, jobQueue, logger, nil, scanVulnRepo)
	scanService := services.NewScanService(scanRepo, sbomRepo, scanWorker)

	signingKeyPath := filepath.Join(os.TempDir(), "bdd-signing-key")
	signingService := services.NewSigningService(db, logger, signingKeyPath)

	alertHub := services.NewAlertHub(logger)
	csafGenerator := services.NewCSAFGeneratorWithOrg(vulnRepo, feedRepo, slaRepo, orgRepo)

	cryptoService, err := services.NewCryptoService(testEncryptionKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to init crypto service: %w", err)
	}

	enisaService := services.NewENISAService(orgRepo, subRepo, csafGenerator, cryptoService, logger, 0, 0, 0)
	disclosureService := services.NewDisclosureService(disclosureRepo)
	vexService := services.NewVEXService(vexStmtRepo, vexPubRepo, feedRepo, vulnRepo, db, logger, csafGenerator, enisaService)
	slaCalculator := services.NewSlaCalculator(vulnRepo, slaRepo, orgRepo, enisaService, db, logger, 0)
	alertService := services.NewAlertService(alertHub, slaRepo, vulnRepo, eventRepo, orgRepo, signingService, logger, 0)
	telemetryService := services.NewTelemetryService(telemetryRepo, alertHub, logger)
	tierService := services.NewTierService(greenboneRepo, sbomWebhookRepo, logger)
	greenboneService := services.NewGreenboneService(greenboneRepo, scanRepo, vulnRepo, alertHub, telemetryService, db, logger)
	greenboneService.SetCSAFGenerator(csafGenerator)

	csafProviderHandler := rest.NewCSAFProviderHandler(subRepo, orgRepo, csafGenerator, logger, "http://localhost:8080")

	alertHandler := rest.NewAlertHandler(alertHub, testJWTSecret)
	enisaHandler := rest.NewENISAHandler(enisaService, subRepo, logger)
	greenboneHandler := rest.NewGreenboneHandler(greenboneService, greenboneRepo, orgRepo, tierService)
	sbomWebhookHandler := rest.NewSbomWebhookHandler(sbomWebhookRepo, sbomRepo, scanService, telemetryService, alertHub, orgRepo, tierService, int64(10*1024*1024))
	telemetryHandler := rest.NewTelemetryHandler(telemetryRepo, telemetryService, logger)

	greenboneUpdater := middleware.NewLastUsedAtUpdater(db, logger, "compliance.greenbone_webhooks")
	sbomWebhookUpdater := middleware.NewLastUsedAtUpdater(db, logger, "compliance.sbom_webhooks")

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

	rateLimiter := middleware.NewIPRateLimiter(rate.Every(time.Minute), 10000)
	router.Use(middleware.RateLimitMiddleware(rateLimiter))
	router.Use(rest.ErrorRecoveryMiddleware(logger))
	router.Use(config.LoggingMiddleware(logger))

	router.GET("/health", func(c *gin.Context) {
		sqlDB, err := db.DB()
		if err != nil || sqlDB.PingContext(c.Request.Context()) != nil {
			c.Header("Content-Type", "application/problem+json")
			c.JSON(503, api.ProblemDetail{
				Type:   "about:blank",
				Title:  "Service Unavailable",
				Status: 503,
				Detail: "database unreachable",
			})
			return
		}

		c.Header("Content-Type", "application/problem+json")
		c.JSON(200, api.ProblemDetail{
			Type:   "about:blank",
			Title:  "OK",
			Status: 200,
			Detail: "service is healthy",
		})
	})

	router.GET("/ready", func(c *gin.Context) {
		c.Header("Content-Type", "application/problem+json")
		c.JSON(200, gin.H{"status": "service is ready"})
	})

	router.GET("/api/v1/telemetry/metrics", telemetryHandler.GetMetricsByToken)

	// CSAF v2.0 public provider endpoints (no auth)
	wellKnown := router.Group("/.well-known/csaf")
	{
		wellKnown.GET("/:org_slug/provider-metadata.json", csafProviderHandler.WellKnownProviderMetadata)
		wellKnown.GET("/:org_slug/changes.csv", csafProviderHandler.WellKnownChanges)
		wellKnown.GET("/:org_slug/:advisory_id.json", csafProviderHandler.WellKnownAdvisory)
	}

	apiGroup := router.Group("/api")
	apiGroup.Use(middleware.JWTMiddleware(testJWTSecret))
	apiGroup.Use(middleware.TenantMiddleware())
	apiGroup.Use(middleware.ParseOrgIDMiddleware())
	{
		scanHandler := rest.NewScanHandlerWithVulns(scanService, scanVulnRepo, logger)
		apiGroup.POST("/scan", scanHandler.CreateScan)
		apiGroup.GET("/scans", scanHandler.ListScans)
		apiGroup.GET("/scans/:id/vulnerabilities", scanHandler.GetScanVulnerabilities)

		sbomHandler := rest.NewSbomHandler(sbomRepo, int64(10*1024*1024), nil, alertHub)
		apiGroup.POST("/sboms/upload", sbomHandler.Upload)
		apiGroup.GET("/sboms", sbomHandler.List)
		apiGroup.GET("/sboms/:id", sbomHandler.GetByID)
		apiGroup.GET("/sboms/:id/download", sbomHandler.Download)
		apiGroup.DELETE("/sboms/:id", sbomHandler.Delete)

		vulnHandler := rest.NewVulnerabilityHandler(vulnRepo, grcRepo)
		apiGroup.GET("/vulnerabilities", vulnHandler.ListVulnerabilities)
		apiGroup.GET("/vulnerabilities/:cve", vulnHandler.GetVulnerability)

		complianceHandler := rest.NewComplianceHandler(slaRepo, vulnRepo, eventRepo, orgRepo, grcRepo, logger)
		apiGroup.GET("/compliance/status", complianceHandler.GetComplianceStatus)
		apiGroup.GET("/compliance/sla", complianceHandler.ListSlaTracking)

		orgHandler := rest.NewOrganizationHandler(orgRepo, logger)
		apiGroup.GET("/orgs/support-period", orgHandler.GetSupportPeriod)

		apiGroup.GET("/enisa/submissions", enisaHandler.ListSubmissions)
		apiGroup.GET("/enisa/submissions/:id", enisaHandler.GetSubmission)
		apiGroup.GET("/enisa/submissions/:id/download", enisaHandler.DownloadSubmission)

		apiGroup.GET("/alerts/stream", alertHandler.StreamAlerts)

		disclosureHandler := rest.NewDisclosureHandler(disclosureService, logger)
		apiGroup.POST("/disclosures", disclosureHandler.CreateDisclosure)
		apiGroup.GET("/disclosures", disclosureHandler.ListDisclosures)
		apiGroup.GET("/disclosures/sla-compliance", disclosureHandler.CheckSLACompliance)
		apiGroup.GET("/disclosures/:id", disclosureHandler.GetDisclosure)
		apiGroup.PUT("/disclosures/:id/status", disclosureHandler.UpdateStatus)

		vexHandler := rest.NewVEXHandler(vexService, vexStmtRepo, logger)
		apiGroup.POST("/vex", vexHandler.CreateVEX)
		apiGroup.GET("/vex", vexHandler.ListVEX)

		feedStatusHandler := rest.NewFeedStatusHandler(feedRepo)
		apiGroup.GET("/feeds/status", feedStatusHandler.GetStatus)

		apiGroup.GET("/csaf/provider-metadata.json", csafProviderHandler.GetProviderMetadata)
		apiGroup.GET("/csaf/advisories", csafProviderHandler.ListAdvisories)
		apiGroup.GET("/csaf/advisories/:id", csafProviderHandler.GetAdvisory)
		apiGroup.GET("/csaf/changes.csv", csafProviderHandler.GetChanges)

		auditHandler := rest.NewAuditHandler(signingService)
		apiGroup.GET("/audit/verify", auditHandler.VerifyAuditChain)

		signingHandler := rest.NewSigningHandler(signingService, logger)
		apiGroup.DELETE("/organisations/:org_id/signing-keys/:key_id", signingHandler.RevokeKey)

		apiGroup.POST("/greenbone/webhooks", greenboneHandler.CreateWebhook)
		apiGroup.GET("/greenbone/webhooks", greenboneHandler.ListWebhooks)
		apiGroup.DELETE("/greenbone/webhooks/:id", greenboneHandler.DeleteWebhook)

		apiGroup.POST("/sbom/webhooks", sbomWebhookHandler.CreateSbomWebhook)
		apiGroup.GET("/sbom/webhooks", sbomWebhookHandler.ListSbomWebhooks)
		apiGroup.DELETE("/sbom/webhooks/:id", sbomWebhookHandler.DeleteSbomWebhook)

		apiGroup.POST("/telemetry/config", telemetryHandler.CreateOrUpdateConfig)
		apiGroup.GET("/telemetry/config", telemetryHandler.GetConfig)
		apiGroup.POST("/telemetry/config/rotate-token", telemetryHandler.RotateToken)
	}

	admin := apiGroup.Group("/")
	admin.Use(middleware.RequireRole("admin"))
	{
		orgHandler := rest.NewOrganizationHandler(orgRepo, logger)
		admin.PUT("/orgs/support-period", orgHandler.UpdateSupportPeriod)
		admin.POST("/enisa/submit", enisaHandler.Submit)
	}

	complianceGroup := apiGroup.Group("/")
	complianceGroup.Use(middleware.RequireRole("admin", "compliance_officer"))
	{
		complianceHandler := rest.NewComplianceHandler(slaRepo, vulnRepo, eventRepo, orgRepo, grcRepo, logger)
		complianceGroup.POST("/compliance/exploited", complianceHandler.ReportExploitedVulnerability)

		pdfService := services.NewPDFService(logger)
		exportHandler := rest.NewExportHandler(eventRepo, orgRepo, sbomRepo, grcRepo, &pdfAdapter{pdfService: pdfService})
		complianceGroup.GET("/export/audit", exportHandler.ExportAudit)
		complianceGroup.GET("/export/enriched-sbom/:sbom_id", exportHandler.ExportEnrichedSBOM)

		vexHandler := rest.NewVEXHandler(vexService, vexStmtRepo, logger)
		complianceGroup.POST("/vex/:id/approve", vexHandler.ApproveVEX)
		complianceGroup.POST("/vex/:id/publish", vexHandler.PublishVEX)
	}

	webhookV1 := router.Group("/api/v1")
	webhookV1.POST("/greenbone/webhook/:id", middleware.GreenboneAuthMiddleware(db, greenboneUpdater), greenboneHandler.HandleWebhook)
	webhookV1.POST("/sbom/webhook/:id", middleware.SbomWebhookAuthMiddleware(db, sbomWebhookUpdater), sbomWebhookHandler.HandleUpload)

	workersCtx, cancel := context.WithCancel(ctx)

	go greenboneUpdater.Start(workersCtx)
	go sbomWebhookUpdater.Start(workersCtx)
	go scanWorker.Start(workersCtx)
	go slaCalculator.Start(workersCtx)
	go alertService.Start(workersCtx)
	go enisaService.StartRetryWorker(workersCtx)
	go vunnelSync.Start(workersCtx)

	return router, alertHub, cancel, nil
}
