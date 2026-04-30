// transparenz-server-oss — Open-source CRA/NIS2 compliance reporting server.
//
// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
// This is the open-source edition. The commercial edition adds:
// ENISA submission, Greenbone integration, SBOM webhooks, telemetry,
// PDF reports, signing key management, and per-org rate limiting.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	apiPkg "github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/internal/api/rest"
	"github.com/transparenz/transparenz-server-oss/internal/config"
	"github.com/transparenz/transparenz-server-oss/pkg/interfaces"
	"github.com/transparenz/transparenz-server-oss/internal/jobs"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"github.com/transparenz/transparenz-server-oss/internal/services"
	"go.uber.org/zap"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "transparenz-server-oss",
		Short: "Open-source EU CRA/NIS2 compliance reporting server",
		Run: func(cmd *cobra.Command, args []string) {
			runServer()
		},
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServer() {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := config.InitLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck

	db, err := config.InitDB(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal("failed to initialize database", zap.Error(err))
	}

	// Repositories
	scanRepo := repository.NewScanRepository(db)
	sbomRepo := repository.NewSbomRepository(db)
	scanVulnRepo := repository.NewScanVulnerabilityRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	vulnFeedRepo := repository.NewVulnerabilityFeedRepository(db)
	eventRepo := repository.NewComplianceEventRepository(db)
	slaRepo := repository.NewSlaTrackingRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	vexStmtRepo := repository.NewVexStatementRepository(db)
	vexPubRepo := repository.NewVexPublicationRepository(db)
	disclosureRepo := repository.NewVulnerabilityDisclosureRepository(db)
	enisaSubRepo := repository.NewEnisaSubmissionRepository(db)
	grcRepo := repository.NewGRCMappingRepository(db)

	// Jobs
	jobQueue := jobs.NewJobQueue(db, logger, 5*time.Second)

	// Services
	alertHub := services.NewAlertHub(logger)
	signingService := services.NewSigningService()
	enisaService := services.NewENISAService()
	csafGenerator := services.NewCSAFGeneratorWithOrg(vulnRepo, vulnFeedRepo, slaRepo, orgRepo)

	scanWorker := services.NewScanWorker(
		scanRepo, vulnRepo, vulnFeedRepo, sbomRepo,
		jobQueue, logger, nil, scanVulnRepo,
	)
	vulnzMatcher := services.NewVulnzMatcher(vulnFeedRepo, logger)
	scanWorker.SetVulnzMatcher(vulnzMatcher)
	go scanWorker.Start(context.Background())

	scanService := services.NewScanService(scanRepo, sbomRepo, scanWorker)

	vexService := services.NewVEXService(vexStmtRepo, vexPubRepo, vulnFeedRepo, vulnRepo, db, logger, csafGenerator, enisaService)
	disclosureService := services.NewDisclosureService(disclosureRepo)

	slaCalculator := services.NewSlaCalculator(vulnRepo, slaRepo, orgRepo, enisaService, db, logger, 0)
	go slaCalculator.Start(context.Background())

	// Handlers
	scanHandler := rest.NewScanHandlerWithVulns(scanService, scanVulnRepo, logger)
	sbomHandler := rest.NewSbomHandler(sbomRepo, int64(cfg.MaxSBOMSize), alertHub)
	vulnHandler := rest.NewVulnerabilityHandler(vulnRepo, grcRepo)
	complianceHandler := rest.NewComplianceHandler(slaRepo, vulnRepo, eventRepo, orgRepo, grcRepo, logger)
	orgHandler := rest.NewOrganizationHandler(orgRepo, logger)

	// ENISA: use OSS stub as submitter (no-op), repo for read-only
	enisaHandler := rest.NewENISAHandler(interfaces.ENISASubmitter(enisaService), enisaSubRepo, logger)

	alertHandler := rest.NewAlertHandler(alertHub, cfg.JWTSecret)
	disclosureHandler := rest.NewDisclosureHandler(disclosureService, logger)
	feedStatusHandler := rest.NewFeedStatusHandler(vulnFeedRepo)
	csafProviderHandler := rest.NewCSAFProviderHandler(enisaSubRepo, orgRepo, csafGenerator, logger, "")
	csafFeedHandler := rest.NewCSAFFeedIngestionHandler(vulnFeedRepo, logger)
	vexHandler := rest.NewVEXHandler(vexService, vexStmtRepo, logger)
	auditHandler := rest.NewAuditHandler(signingService)
	exportHandler := rest.NewExportHandler(eventRepo, orgRepo, sbomRepo, grcRepo)

	// Router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Middleware stack
	router.Use(rest.ErrorRecoveryMiddleware(logger))
	router.Use(middleware.SecureHeaders())
	router.Use(middleware.DefaultBodyLimit())
	router.Use(middleware.RequestIDMiddleware())
	router.Use(config.LoggingMiddleware(logger))

	// CORS
	router.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.CORSAllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Health endpoint (RFC 7807 ProblemDetail format)
	router.GET("/health", func(c *gin.Context) {
		sqlDB, err := db.DB()
		if err != nil || sqlDB.Ping() != nil {
			c.Header("Content-Type", "application/problem+json")
			c.JSON(http.StatusServiceUnavailable, gin.H{"type": "about:blank", "title": "Service Unavailable", "status": 503, "detail": "database unreachable"})
			return
		}
		c.Header("Content-Type", "application/problem+json")
		c.JSON(http.StatusOK, gin.H{"type": "about:blank", "title": "OK", "status": 200, "detail": "service is healthy"})
	})

		router.GET("/readyz", func(c *gin.Context) {
		sqlDB, err := db.DB()
		if err != nil || sqlDB.Ping() != nil {
			c.Header("Content-Type", "application/problem+json")
			c.JSON(http.StatusServiceUnavailable, gin.H{"type": "about:blank", "title": "Not Ready", "status": 503, "detail": "database disconnected"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "service is ready"})
	})

	// Metrics endpoint (minimal — Prometheus metrics require commercial edition)
	router.GET("/metrics", metricsAuth(cfg), func(c *gin.Context) {
		c.Header("Content-Type", "text/plain")
		c.String(http.StatusOK, "# transparenz-server-oss metrics\n# Prometheus metrics require the commercial edition\n")
	})

	// Authenticated API routes
	api := router.Group("/api")
	api.Use(middleware.JWTMiddleware(cfg.JWTSecret))
	api.Use(middleware.TenantMiddleware())
	api.Use(middleware.ParseOrgIDMiddleware())

	{
		api.POST("/scan", scanHandler.CreateScan)
		api.GET("/scans", scanHandler.ListScans)
		api.GET("/scans/:id/vulnerabilities", scanHandler.GetScanVulnerabilities)

		api.POST("/sboms/upload", sbomHandler.Upload)
		api.GET("/sboms", sbomHandler.List)
		api.GET("/sboms/:id", sbomHandler.GetByID)
		api.GET("/sboms/:id/download", sbomHandler.Download)
		api.DELETE("/sboms/:id", sbomHandler.Delete)

		api.GET("/vulnerabilities", vulnHandler.ListVulnerabilities)
		api.GET("/vulnerabilities/:cve", vulnHandler.GetVulnerability)

		api.GET("/compliance/status", complianceHandler.GetComplianceStatus)
		api.GET("/compliance/sla", complianceHandler.ListSlaTracking)

		api.GET("/orgs/support-period", orgHandler.GetSupportPeriod)

		// ENISA read-only (submission is commercial only)
		api.GET("/enisa/submissions", enisaHandler.ListSubmissions)
		api.GET("/enisa/submissions/:id", enisaHandler.GetSubmission)
		api.GET("/enisa/submissions/:id/download", enisaHandler.DownloadSubmission)
		// ENISA submit stub: returns 403 in OSS (commercial feature)
		api.POST("/enisa/submit", func(c *gin.Context) {
			apiPkg.Forbidden(c, "ENISA submission requires the commercial edition of transparenz-server")
		})

		api.GET("/alerts/stream", alertHandler.StreamAlerts)

		api.POST("/disclosures", disclosureHandler.CreateDisclosure)
		api.GET("/disclosures", disclosureHandler.ListDisclosures)
		api.GET("/disclosures/sla-compliance", disclosureHandler.CheckSLACompliance)
		api.GET("/disclosures/:id", disclosureHandler.GetDisclosure)
		api.PUT("/disclosures/:id/status", disclosureHandler.UpdateStatus)

		api.GET("/feeds/status", feedStatusHandler.GetStatus)

		api.GET("/csaf/provider-metadata.json", csafProviderHandler.GetProviderMetadata)
		api.GET("/csaf/advisories", csafProviderHandler.ListAdvisories)
		api.GET("/csaf/advisories/:id", csafProviderHandler.GetAdvisory)
		api.GET("/csaf/changes.csv", csafProviderHandler.GetChanges)

		api.POST("/vex", vexHandler.CreateVEX)
		api.GET("/vex", vexHandler.ListVEX)

		api.GET("/audit/verify", auditHandler.VerifyAuditChain)
	}

	// Admin routes
	admin := api.Group("/")
	admin.Use(middleware.RequireRole("admin"))
	{
		admin.PUT("/orgs/support-period", orgHandler.UpdateSupportPeriod)
		admin.POST("/csaf/feeds/ingest", csafFeedHandler.IngestFeed)
	}

	// Compliance officer routes
	compliance := api.Group("/")
	compliance.Use(middleware.RequireRole("admin", "compliance_officer"))
	{
		compliance.POST("/compliance/exploited", complianceHandler.ReportExploitedVulnerability)
		compliance.GET("/export/audit", exportHandler.ExportAudit)
		compliance.GET("/export/enriched-sbom/:sbom_id", exportHandler.ExportEnrichedSBOM)
		compliance.POST("/vex/:id/approve", vexHandler.ApproveVEX)
		compliance.POST("/vex/:id/publish", vexHandler.PublishVEX)
	}

	// Start server
	addr := fmt.Sprintf(":%s", cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("starting transparenz-server-oss", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("server forced shutdown", zap.Error(err))
	}
	logger.Info("server exited")
}

// metricsAuth provides basic auth for the /metrics endpoint.
func metricsAuth(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		metricsPass := cfg.MetricsPassword
		if metricsPass == "" {
			metricsPass = "metrics"
		}
		if !ok || user != "metrics" || pass != metricsPass {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}
