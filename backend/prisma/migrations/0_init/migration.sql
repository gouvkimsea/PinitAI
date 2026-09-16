-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'user',
    "status" TEXT NOT NULL DEFAULT 'active',
    "apiKeyHash" TEXT,
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scans" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "type" TEXT NOT NULL,
    "target" TEXT NOT NULL,
    "targetHash" TEXT,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "riskLevel" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "riskScore" INTEGER NOT NULL DEFAULT 0,
    "threatConfidence" TEXT NOT NULL DEFAULT 'LOW',
    "threatCategory" TEXT,
    "errorMessage" TEXT,
    "scanDurationMs" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "files" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "originalName" TEXT NOT NULL,
    "sanitizedName" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "detectedMimeType" TEXT,
    "sizeBytes" INTEGER NOT NULL,
    "extension" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "files_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "file_hashes" (
    "id" TEXT NOT NULL,
    "fileId" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "sha1" TEXT NOT NULL,
    "md5" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "file_hashes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "url_scans" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "normalizedUrl" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "ipAddress" TEXT,
    "isHttps" BOOLEAN NOT NULL DEFAULT false,
    "hasRedirects" BOOLEAN NOT NULL DEFAULT false,
    "redirectCount" INTEGER NOT NULL DEFAULT 0,
    "domainAgeDays" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "url_scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "detections" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "modelVersionId" TEXT,
    "engine" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "score" INTEGER NOT NULL DEFAULT 0,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "executionMs" INTEGER,
    "details" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "detections_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_results" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "totalEngines" INTEGER NOT NULL DEFAULT 0,
    "maliciousEngines" INTEGER NOT NULL DEFAULT 0,
    "suspiciousEngines" INTEGER NOT NULL DEFAULT 0,
    "cleanEngines" INTEGER NOT NULL DEFAULT 0,
    "safeFactors" TEXT NOT NULL DEFAULT '[]',
    "recommendations" TEXT NOT NULL DEFAULT '[]',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "analysis_evidence" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "indicators" TEXT NOT NULL DEFAULT '[]',
    "evidenceBreakdown" TEXT NOT NULL DEFAULT '{}',
    "technicalEvidence" TEXT NOT NULL DEFAULT '{}',
    "uncertaintyNotes" TEXT,
    "groundedScore" INTEGER NOT NULL DEFAULT 100,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "analysis_evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scam_patterns" (
    "id" TEXT NOT NULL,
    "pattern" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "matchCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scam_patterns_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scam_reports" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "scamType" TEXT NOT NULL,
    "target" TEXT,
    "targetHash" TEXT,
    "description" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "reviewedBy" TEXT,
    "reviewNotes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scam_reports_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "analysis_feedback" (
    "id" TEXT NOT NULL,
    "analysisId" TEXT NOT NULL,
    "userId" TEXT,
    "ipHash" TEXT,
    "feedbackType" TEXT NOT NULL,
    "reportedCategory" TEXT,
    "explanation" TEXT,
    "targetSnippet" TEXT,
    "riskScoreAtTime" INTEGER,
    "isReviewed" BOOLEAN NOT NULL DEFAULT false,
    "reviewedBy" TEXT,
    "reviewNote" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "analysis_feedback_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "model_versions" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "modelType" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "capabilities" TEXT NOT NULL DEFAULT '[]',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "model_versions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_usage" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "apiKeyHash" TEXT,
    "endpoint" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "statusCode" INTEGER NOT NULL,
    "durationMs" INTEGER NOT NULL,
    "requestCount" INTEGER NOT NULL DEFAULT 1,
    "clientIpHash" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "api_usage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_events" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "eventType" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "ipHash" TEXT,
    "targetResource" TEXT,
    "details" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "threat_intelligence" (
    "id" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetValue" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "reputationScore" INTEGER NOT NULL DEFAULT 0,
    "threatCategory" TEXT,
    "rawData" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "threat_intelligence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_logs" (
    "id" TEXT NOT NULL,
    "endpoint" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "statusCode" INTEGER NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "durationMs" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "api_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "users_apiKeyHash_key" ON "users"("apiKeyHash");

-- CreateIndex
CREATE INDEX "users_role_idx" ON "users"("role");

-- CreateIndex
CREATE INDEX "users_status_idx" ON "users"("status");

-- CreateIndex
CREATE INDEX "users_createdAt_idx" ON "users"("createdAt");

-- CreateIndex
CREATE INDEX "scans_status_idx" ON "scans"("status");

-- CreateIndex
CREATE INDEX "scans_riskLevel_idx" ON "scans"("riskLevel");

-- CreateIndex
CREATE INDEX "scans_riskLevel_createdAt_idx" ON "scans"("riskLevel", "createdAt");

-- CreateIndex
CREATE INDEX "scans_type_idx" ON "scans"("type");

-- CreateIndex
CREATE INDEX "scans_targetHash_idx" ON "scans"("targetHash");

-- CreateIndex
CREATE INDEX "scans_targetHash_status_createdAt_idx" ON "scans"("targetHash", "status", "createdAt");

-- CreateIndex
CREATE INDEX "scans_status_createdAt_idx" ON "scans"("status", "createdAt");

-- CreateIndex
CREATE INDEX "scans_type_createdAt_idx" ON "scans"("type", "createdAt");

-- CreateIndex
CREATE INDEX "scans_userId_createdAt_idx" ON "scans"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "scans_createdAt_idx" ON "scans"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "files_scanId_key" ON "files"("scanId");

-- CreateIndex
CREATE INDEX "files_extension_idx" ON "files"("extension");

-- CreateIndex
CREATE INDEX "files_sizeBytes_idx" ON "files"("sizeBytes");

-- CreateIndex
CREATE UNIQUE INDEX "file_hashes_fileId_key" ON "file_hashes"("fileId");

-- CreateIndex
CREATE INDEX "file_hashes_sha256_idx" ON "file_hashes"("sha256");

-- CreateIndex
CREATE INDEX "file_hashes_md5_idx" ON "file_hashes"("md5");

-- CreateIndex
CREATE UNIQUE INDEX "url_scans_scanId_key" ON "url_scans"("scanId");

-- CreateIndex
CREATE INDEX "url_scans_domain_idx" ON "url_scans"("domain");

-- CreateIndex
CREATE INDEX "url_scans_isHttps_idx" ON "url_scans"("isHttps");

-- CreateIndex
CREATE INDEX "detections_scanId_idx" ON "detections"("scanId");

-- CreateIndex
CREATE INDEX "detections_scanId_severity_idx" ON "detections"("scanId", "severity");

-- CreateIndex
CREATE INDEX "detections_engine_idx" ON "detections"("engine");

-- CreateIndex
CREATE INDEX "detections_category_idx" ON "detections"("category");

-- CreateIndex
CREATE INDEX "detections_severity_idx" ON "detections"("severity");

-- CreateIndex
CREATE INDEX "detections_modelVersionId_idx" ON "detections"("modelVersionId");

-- CreateIndex
CREATE UNIQUE INDEX "scan_results_scanId_key" ON "scan_results"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "analysis_evidence_scanId_key" ON "analysis_evidence"("scanId");

-- CreateIndex
CREATE INDEX "scam_patterns_category_idx" ON "scam_patterns"("category");

-- CreateIndex
CREATE INDEX "scam_patterns_status_idx" ON "scam_patterns"("status");

-- CreateIndex
CREATE INDEX "scam_patterns_severity_idx" ON "scam_patterns"("severity");

-- CreateIndex
CREATE INDEX "scam_reports_scamType_idx" ON "scam_reports"("scamType");

-- CreateIndex
CREATE INDEX "scam_reports_status_idx" ON "scam_reports"("status");

-- CreateIndex
CREATE INDEX "scam_reports_targetHash_idx" ON "scam_reports"("targetHash");

-- CreateIndex
CREATE INDEX "scam_reports_createdAt_idx" ON "scam_reports"("createdAt");

-- CreateIndex
CREATE INDEX "analysis_feedback_analysisId_idx" ON "analysis_feedback"("analysisId");

-- CreateIndex
CREATE INDEX "analysis_feedback_feedbackType_idx" ON "analysis_feedback"("feedbackType");

-- CreateIndex
CREATE INDEX "analysis_feedback_userId_idx" ON "analysis_feedback"("userId");

-- CreateIndex
CREATE INDEX "analysis_feedback_ipHash_idx" ON "analysis_feedback"("ipHash");

-- CreateIndex
CREATE INDEX "analysis_feedback_isReviewed_idx" ON "analysis_feedback"("isReviewed");

-- CreateIndex
CREATE INDEX "analysis_feedback_createdAt_idx" ON "analysis_feedback"("createdAt");

-- CreateIndex
CREATE INDEX "model_versions_modelType_isActive_idx" ON "model_versions"("modelType", "isActive");

-- CreateIndex
CREATE INDEX "model_versions_provider_idx" ON "model_versions"("provider");

-- CreateIndex
CREATE UNIQUE INDEX "model_versions_name_version_key" ON "model_versions"("name", "version");

-- CreateIndex
CREATE INDEX "api_usage_apiKeyHash_createdAt_idx" ON "api_usage"("apiKeyHash", "createdAt");

-- CreateIndex
CREATE INDEX "api_usage_userId_createdAt_idx" ON "api_usage"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "api_usage_endpoint_createdAt_idx" ON "api_usage"("endpoint", "createdAt");

-- CreateIndex
CREATE INDEX "api_usage_statusCode_idx" ON "api_usage"("statusCode");

-- CreateIndex
CREATE INDEX "api_usage_createdAt_idx" ON "api_usage"("createdAt");

-- CreateIndex
CREATE INDEX "security_events_eventType_createdAt_idx" ON "security_events"("eventType", "createdAt");

-- CreateIndex
CREATE INDEX "security_events_severity_createdAt_idx" ON "security_events"("severity", "createdAt");

-- CreateIndex
CREATE INDEX "security_events_ipHash_createdAt_idx" ON "security_events"("ipHash", "createdAt");

-- CreateIndex
CREATE INDEX "security_events_userId_createdAt_idx" ON "security_events"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "threat_intelligence_targetType_targetValue_idx" ON "threat_intelligence"("targetType", "targetValue");

-- CreateIndex
CREATE INDEX "threat_intelligence_targetType_targetValue_expiresAt_idx" ON "threat_intelligence"("targetType", "targetValue", "expiresAt");

-- CreateIndex
CREATE INDEX "threat_intelligence_expiresAt_idx" ON "threat_intelligence"("expiresAt");

-- CreateIndex
CREATE INDEX "api_logs_createdAt_idx" ON "api_logs"("createdAt");

-- CreateIndex
CREATE INDEX "api_logs_endpoint_createdAt_idx" ON "api_logs"("endpoint", "createdAt");

-- CreateIndex
CREATE INDEX "api_logs_statusCode_createdAt_idx" ON "api_logs"("statusCode", "createdAt");

-- AddForeignKey
ALTER TABLE "scans" ADD CONSTRAINT "scans_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "files" ADD CONSTRAINT "files_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "file_hashes" ADD CONSTRAINT "file_hashes_fileId_fkey" FOREIGN KEY ("fileId") REFERENCES "files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "url_scans" ADD CONSTRAINT "url_scans_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detections" ADD CONSTRAINT "detections_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detections" ADD CONSTRAINT "detections_modelVersionId_fkey" FOREIGN KEY ("modelVersionId") REFERENCES "model_versions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "analysis_evidence" ADD CONSTRAINT "analysis_evidence_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scam_reports" ADD CONSTRAINT "scam_reports_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "analysis_feedback" ADD CONSTRAINT "analysis_feedback_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "api_usage" ADD CONSTRAINT "api_usage_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

