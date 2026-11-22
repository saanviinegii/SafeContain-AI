/**
 * SafeContain AI Frontend REST API Client.
 * Connects directly to FastAPI backend /api/v1/ endpoints.
 * Automatically resolves endpoint URL across local dev, static preview, and unified cloud production.
 * Supports persistent JWT Bearer token authentication and role-based privilege checks.
 */

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  role: 'ADMIN' | 'ANALYST' | 'VIEWER';
  is_active: boolean;
  full_name: string;
  created_at?: string;
  updated_at?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: AuthUser;
}

const TOKEN_KEY = 'safecontain_access_token';
const USER_KEY = 'safecontain_auth_user';

export function getStoredToken(): string | null {
  if (typeof window === 'undefined' || !window.localStorage) return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token: string | null): void {
  if (typeof window === 'undefined' || !window.localStorage) return;
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export function getStoredUser(): AuthUser | null {
  if (typeof window === 'undefined' || !window.localStorage) return null;
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function setStoredUser(user: AuthUser | null): void {
  if (typeof window === 'undefined' || !window.localStorage) return;
  if (user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } else {
    localStorage.removeItem(USER_KEY);
  }
}

export function clearSession(): void {
  setStoredToken(null);
  setStoredUser(null);
}

export function resolveApiBase(): string {
  // 1. Explicit environment variable takes absolute priority
  const envUrl = ((import.meta as any).env?.VITE_API_BASE_URL as string | undefined)?.replace(/\/+$/, '');
  if (envUrl) {
    return envUrl.endsWith('/api/v1') ? envUrl : `${envUrl}/api/v1`;
  }

  // 2. Intelligent browser runtime detection
  if (typeof window !== 'undefined' && window.location) {
    const { hostname, port, origin } = window.location;

    // If opened from a standalone dev/preview static server on 5173 or 3000:
    // Route API requests directly to local FastAPI backend on port 8000
    if ((hostname === 'localhost' || hostname === '127.0.0.1') && (port === '5173' || port === '3000')) {
      return 'http://127.0.0.1:8000/api/v1';
    }

    // If opened via local file protocol or raw origin:
    if (origin === 'null' || !origin.startsWith('http')) {
      return 'https://safecontain-ai.onrender.com/api/v1';
    }
  }

  // 3. Unified production deployment (Render Cloud or FastAPI serving static assets on same port)
  return '/api/v1';
}

export async function fetchApi<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const base = resolveApiBase();
  const url = `${base}${cleanEndpoint}`;

  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options.headers as Record<string, string>) || {}),
  };
  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const errorBody = await response.text();
    if (response.status === 401 && typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('safecontain:unauthorized'));
    }
    throw new Error(`API Error [${response.status}] ${response.statusText}: ${errorBody}`);
  }

  return response.json();
}

export const api = {
  // Authentication & User Management
  login: async (username: string, password: string): Promise<TokenResponse> => {
    const res = await fetchApi<TokenResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    setStoredToken(res.access_token);
    setStoredUser(res.user);
    return res;
  },
  logout: () => {
    clearSession();
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('safecontain:logout'));
    }
  },
  getMe: () => fetchApi<AuthUser>('/auth/me'),
  getUsers: () => fetchApi<AuthUser[]>('/auth/users'),
  createUser: (req: { username: string; password: string; role: string; email?: string; full_name?: string }) =>
    fetchApi<AuthUser>('/auth/users', { method: 'POST', body: JSON.stringify(req) }),
  updateUserRole: (userId: string, role: string) =>
    fetchApi<AuthUser>(`/auth/users/${encodeURIComponent(userId)}/role`, { method: 'PUT', body: JSON.stringify({ role }) }),
  updateUserStatus: (userId: string, isActive: boolean) =>
    fetchApi<AuthUser>(`/auth/users/${encodeURIComponent(userId)}/status`, { method: 'PATCH', body: JSON.stringify({ is_active: isActive }) }),

  // System & Observability
  getHealth: () => fetchApi<any>('/health'),
  getMetrics: () => fetchApi<any>('/metrics'),

  // Scenarios & Graph Operations
  loadSyntheticScenario: (name?: string) =>
    fetchApi<any>(`/scenario/load-synthetic${name ? `?scenario_name=${encodeURIComponent(name)}` : ''}`, { method: 'POST' }),
  loadDemoScenario: () => fetchApi<any>('/scenario/load-demo', { method: 'POST' }),
  getTopology: () => fetchApi<{ nodes: any[]; edges: any[]; backend: string }>('/graph/topology'),
  getNeo4jStatus: () => fetchApi<any>('/graph/neo4j/status'),
  getNeo4jStatistics: () => fetchApi<any>('/graph/neo4j/statistics'),
  syncNeo4j: () => fetchApi<any>('/graph/neo4j/sync', { method: 'POST' }),
  loadFromNeo4j: () => fetchApi<any>('/graph/neo4j/load', { method: 'POST' }),
  getAttackPaths: () => fetchApi<any[]>('/graph/attack-paths'),

  // Evidence & Risk
  getEvidenceSensitivity: () => fetchApi<any[]>('/evidence/sensitivity'),
  getDecomposedRisk: () => fetchApi<any>('/risk/decompose'),
  getWorkflows: () => fetchApi<any[]>('/business/workflows'),

  // Planning & Optimization
  getCandidateActions: () => fetchApi<any[]>('/planning/candidates'),
  optimizeContainment: (budgetLimit: number, strategy: string) =>
    fetchApi<any>('/planning/optimize', {
      method: 'POST',
      body: JSON.stringify({ budget_limit: budgetLimit, strategy }),
    }),

  // Simulation & Explanation
  runSimulation: (req?: { action_ids?: string[]; strategy?: string; budget_limit?: number }) =>
    fetchApi<any>('/simulation/run', {
      method: 'POST',
      body: req ? JSON.stringify(req) : undefined,
    }),
  getExplanation: () => fetchApi<any>('/explanation/recommendation'),

  // Multi-tier Governance
  transitionGovernance: (targetStatus: string, actorRole: string, notes: string) =>
    fetchApi<any>('/governance/transition', {
      method: 'POST',
      body: JSON.stringify({
        target_status: targetStatus,
        actor_id: 'sec-lead-saanvi',
        actor_role: actorRole,
        notes,
      }),
    }),

  // Cryptographic Audit & Blockchain Anchoring
  getAuditLedger: (limit = 50) => fetchApi<any[]>(`/audit/ledger?limit=${limit}`),
  verifyAuditIntegrity: () => fetchApi<any>('/audit/verify'),
  getBlockchainStatus: () => fetchApi<any>('/audit/blockchain/status'),
  getBlockchainRecords: () => fetchApi<any[]>('/audit/blockchain/records'),
  verifyBlockchainRecord: (eventId: string) =>
    fetchApi<any>(`/audit/blockchain/verify?event_id=${encodeURIComponent(eventId)}`, { method: 'POST' }),

  // Phase 3 — Real Blockchain Trust & Evidence Integrity
  getBlockchainNetwork: () => fetchApi<any>('/blockchain/network'),
  getBlockchainAnchorPreview: (maxRecords = 50) => fetchApi<any>(`/blockchain/anchor-preview?max_records=${maxRecords}`),
  listBlockchainAnchors: () => fetchApi<any[]>('/blockchain/anchors'),
  getBlockchainAnchor: (anchorId: string) => fetchApi<any>(`/blockchain/anchors/${encodeURIComponent(anchorId)}`),
  createBlockchainAnchor: (payload: { first_sequence?: number; last_sequence?: number; max_records?: number; submit_on_chain?: boolean; notes?: string }) =>
    fetchApi<any>('/blockchain/anchors', { method: 'POST', body: JSON.stringify(payload) }),
  getEventMerkleProof: (eventId: string, anchorId?: string) =>
    fetchApi<any>(`/blockchain/merkle-proof/${encodeURIComponent(eventId)}${anchorId ? `?anchor_id=${encodeURIComponent(anchorId)}` : ''}`),
  verifyBlockchainEvidence: (payload: { event_id: string; anchor_id?: string }) =>
    fetchApi<any>('/blockchain/verify-evidence', { method: 'POST', body: JSON.stringify(payload) }),
  runBlockchainTamperDemo: (payload: { event_id?: string; field_to_tamper?: string; tampered_value?: string }) =>
    fetchApi<any>('/blockchain/tamper-demo', { method: 'POST', body: JSON.stringify(payload) }),
  getBlockchainLedgerIntegrity: () => fetchApi<any>('/blockchain/ledger-integrity'),

  // Dossier Export
  exportReport: (format: 'json' | 'csv' | 'text') => fetchApi<any>(`/reports/export?format=${format}`),

  // Telemetry Ingestion Connectors
  getConnectors: () => fetchApi<any[]>('/ingestion/connectors'),
  ingestSiem: (payload: any[]) =>
    fetchApi<any>('/ingestion/siem', { method: 'POST', body: JSON.stringify(payload) }),
  ingestEdr: (payload: any[]) =>
    fetchApi<any>('/ingestion/edr', { method: 'POST', body: JSON.stringify(payload) }),
  ingestIam: (payload: any[]) =>
    fetchApi<any>('/ingestion/iam', { method: 'POST', body: JSON.stringify(payload) }),

  // Enterprise Synthetic Dataset Catalog
  getDatasetStatus: () => fetchApi<any>('/dataset/status'),
  getDatasetValidation: () => fetchApi<any>('/dataset/validation'),
  getDatasetScenarios: () => fetchApi<any[]>('/dataset/scenarios'),
  importEnterpriseDataset: (scenarioId?: string) =>
    fetchApi<any>(`/dataset/import${scenarioId ? `?scenario_id=${encodeURIComponent(scenarioId)}` : ''}`, { method: 'POST' }),
  loadThreatScenario: (scenarioId: string) =>
    fetchApi<any>(`/dataset/scenarios/${encodeURIComponent(scenarioId)}/load`, { method: 'POST' }),
  resetDataset: () => fetchApi<any>('/dataset/reset', { method: 'POST' }),
  getDatasetAssets: () => fetchApi<any[]>('/dataset/assets'),
  getDatasetUsers: () => fetchApi<any[]>('/dataset/users'),
  getDatasetVulnerabilities: () => fetchApi<any[]>('/dataset/vulnerabilities'),
  getDatasetAlerts: () => fetchApi<any[]>('/dataset/alerts'),
  getDatasetEvidence: () => fetchApi<any[]>('/dataset/evidence'),
  getDatasetInterventions: () => fetchApi<any[]>('/dataset/interventions'),
  getDatasetDependencies: () => fetchApi<any[]>('/dataset/dependencies'),
  getDatasetBusinessImpact: () => fetchApi<any[]>('/dataset/business-impact'),
  getDatasetDownloadUrl: (filename: string) => `${resolveApiBase()}/dataset/download/${encodeURIComponent(filename)}`,
  getDatasetDownloadAllUrl: () => `${resolveApiBase()}/dataset/download-all`,

  // Incremental CSV Upload
  uploadCsv: async (file: File, overrideProvenance?: string): Promise<CSVIngestionSummary> => {
    const formData = new FormData();
    formData.append('file', file);
    if (overrideProvenance) {
      formData.append('override_provenance', overrideProvenance);
    }
    const base = resolveApiBase();
    const token = getStoredToken();
    const headers: Record<string, string> = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const response = await fetch(`${base}/ingestion/csv`, {
      method: 'POST',
      headers,
      body: formData,
    });
    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Upload Failed [${response.status}] ${response.statusText}: ${errorBody}`);
    }
    return response.json();
  },

  // Machine Learning, Explainability & ML-Powered Containment (Phase 7.2C)
  getMlHealth: () => fetchApi<any>('/ml/health'),
  getMlGraphRisk: () => fetchApi<any>('/ml/graph-risk'),
  getMlAssetRisk: (assetId: string) => fetchApi<any>(`/ml/assets/${encodeURIComponent(assetId)}/risk`),
  getMlAssetExplanation: (assetId: string, topN: number = 5) =>
    fetchApi<any>(`/ml/assets/${encodeURIComponent(assetId)}/explanation?top_n=${topN}`),
  explainAssets: (nodeIds?: string[], topN: number = 5, threshold?: number) =>
    fetchApi<any>('/ml/explain', {
      method: 'POST',
      body: JSON.stringify({ node_ids: nodeIds, top_n: topN, threshold }),
    }),
  getMlCalibration: () => fetchApi<any>('/ml/calibration'),
  optimizeMlContainment: (budgetLimit: number = 10000, thresholdOverride?: number) =>
    fetchApi<any>('/ml/containment/optimize', {
      method: 'POST',
      body: JSON.stringify({ budget_limit: budgetLimit, threshold_override: thresholdOverride }),
    }),

  // Phase 7.2D: Drift Detection, Retraining Governance & Incident Dossier Export
  getDriftStatus: () => fetchApi<any>('/ml/drift/status'),
  getDriftHistory: () => fetchApi<any>('/ml/drift/history'),
  runDriftAnalysis: (datasetLabel: string = 'LIVE_TELEMETRY') =>
    fetchApi<any>('/ml/drift/run', {
      method: 'POST',
      body: JSON.stringify({ dataset_label: datasetLabel }),
    }),
  requestRetraining: (params: {
    feature_subset?: string;
    cv_folds?: number;
    test_size?: number;
    trigger_type?: string;
    candidate_model_type?: string;
    user_notes?: string;
  }) =>
    fetchApi<any>('/ml/retrain/request', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  getRetrainingJobs: () => fetchApi<any>('/ml/retrain/jobs'),
  compareModels: (challengerVersion?: string) =>
    fetchApi<any>(
      challengerVersion
        ? `/ml/retrain/compare?challenger_version=${encodeURIComponent(challengerVersion)}`
        : '/ml/retrain/compare'
    ),
  approveModelPromotion: (challengerVersion: string, approvalNotes?: string) =>
    fetchApi<any>('/ml/retrain/approve', {
      method: 'POST',
      body: JSON.stringify({
        challenger_version: challengerVersion,
        approval_notes: approvalNotes || '',
      }),
    }),
  rejectModel: (challengerVersion: string, rejectionReason: string) =>
    fetchApi<any>('/ml/retrain/reject', {
      method: 'POST',
      body: JSON.stringify({
        challenger_version: challengerVersion,
        rejection_reason: rejectionReason,
      }),
    }),
  rollbackModel: (targetVersion: string, rollbackReason?: string) =>
    fetchApi<any>('/ml/retrain/rollback', {
      method: 'POST',
      body: JSON.stringify({
        target_version: targetVersion,
        rollback_reason: rollbackReason || '',
      }),
    }),
  getModelVersions: () => fetchApi<any>('/ml/models/versions'),
  generateIncidentDossier: (params?: {
    incident_id?: string;
    analyst_name?: string;
    analyst_notes?: string;
    target_scenario?: string;
  }) =>
    fetchApi<any>('/ml/dossier/generate', {
      method: 'POST',
      body: JSON.stringify(params || {}),
    }),
  listIncidentDossiers: () => fetchApi<any>('/ml/dossier/list'),
  getDossierPreview: () => fetchApi<any>('/ml/dossier/preview'),

  // Phase 7.2E: Advanced Threat Intelligence Correlation Engine
  getThreatIntelSummary: () => fetchApi<ThreatIntelSummary>('/threat-intelligence/summary'),
  getThreatIntelIndicators: (params?: { type?: string; severity?: string; min_confidence?: number; search?: string }) => {
    const q = new URLSearchParams();
    if (params?.type) q.append('type', params.type);
    if (params?.severity) q.append('severity', params.severity);
    if (params?.min_confidence !== undefined) q.append('min_confidence', String(params.min_confidence));
    if (params?.search) q.append('search', params.search);
    const qs = q.toString();
    return fetchApi<ThreatIndicator[]>(qs ? `/threat-intelligence/indicators?${qs}` : '/threat-intelligence/indicators');
  },
  getThreatIntelIndicatorDetail: (indicatorId: string) =>
    fetchApi<ThreatIndicator>(`/threat-intelligence/indicators/${encodeURIComponent(indicatorId)}`),
  getThreatIntelCorrelations: (minScore?: number) =>
    fetchApi<ThreatCorrelation[]>(minScore !== undefined ? `/threat-intelligence/correlations?min_score=${minScore}` : '/threat-intelligence/correlations'),
  getThreatIntelClusters: () => fetchApi<IncidentCluster[]>('/threat-intelligence/clusters'),
  getThreatIntelClusterDetail: (clusterId: string) =>
    fetchApi<IncidentCluster>(`/threat-intelligence/clusters/${encodeURIComponent(clusterId)}`),
  runThreatIntelCorrelation: (correlationThreshold: number = 0.40) =>
    fetchApi<any>('/threat-intelligence/correlate', {
      method: 'POST',
      body: JSON.stringify({ correlation_threshold: correlationThreshold }),
    }),
  matchThreatIndicator: (query: string) =>
    fetchApi<any>('/threat-intelligence/match', {
      method: 'POST',
      body: JSON.stringify({ query }),
    }),
  syncThreatIntelToGraph: () =>
    fetchApi<any>('/threat-intelligence/sync-graph', {
      method: 'POST',
    }),

  // Phase 7.3: Temporal Threat Propagation Forecasting
  getForecastSummary: (horizon: string = 'SHORT_TERM') =>
    fetchApi<ForecastingSummary>(`/forecast/summary?horizon=${encodeURIComponent(horizon)}`),
  getAssetForecasts: (params?: { horizon?: string; trend?: string; crown_jewels_only?: boolean; min_probability?: number }) => {
    const q = new URLSearchParams();
    if (params?.horizon) q.append('horizon', params.horizon);
    if (params?.trend) q.append('trend', params.trend);
    if (params?.crown_jewels_only) q.append('crown_jewels_only', 'true');
    if (params?.min_probability !== undefined) q.append('min_probability', String(params.min_probability));
    const qs = q.toString();
    return fetchApi<AssetRiskForecast[]>(qs ? `/forecast/assets?${qs}` : '/forecast/assets');
  },
  getAssetForecastDetail: (assetId: string, horizon: string = 'SHORT_TERM') =>
    fetchApi<AssetRiskForecast>(`/forecast/assets/${encodeURIComponent(assetId)}?horizon=${encodeURIComponent(horizon)}`),
  getPropagationAnalysis: (horizon: string = 'SHORT_TERM', cutoffThreshold: number = 0.35) =>
    fetchApi<any>(`/forecast/propagation?horizon=${encodeURIComponent(horizon)}&cutoff_threshold=${cutoffThreshold}`),
  getForecastHorizons: () => fetchApi<any>('/forecast/horizons'),
  getForecastEvaluation: (horizon: string = 'SHORT_TERM', forceRefresh: boolean = false) =>
    fetchApi<ForecastingEvaluationResult>(`/forecast/evaluate?horizon=${encodeURIComponent(horizon)}&force_refresh=${forceRefresh}`),
  recalculateForecasts: (horizon: string = 'SHORT_TERM') =>
    fetchApi<ForecastingSummary>(`/forecast/recalculate?horizon=${encodeURIComponent(horizon)}`, { method: 'POST' }),
  generatePredictivePlan: (params: { horizon?: string; budget_limit?: number; predictive_weight?: number; threshold_override?: number }) =>
    fetchApi<any>('/forecast/plan', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  // Phase 7.4: Adaptive Threat Intelligence & Predictive Feedback Loop
  getAdaptiveSummary: () =>
    fetchApi<AdaptiveSummary>('/adaptive/summary'),
  getAdaptiveMetrics: (horizon?: string) =>
    fetchApi<{ horizon?: string; metrics: PredictivePerformanceMetrics }>(
      horizon ? `/adaptive/metrics?horizon=${encodeURIComponent(horizon)}` : '/adaptive/metrics'
    ),
  getAdaptivePredictions: (params?: { horizon?: string; status?: string; asset_id?: string; limit?: number; offset?: number }) => {
    const q = new URLSearchParams();
    if (params?.horizon) q.append('horizon', params.horizon);
    if (params?.status) q.append('status', params.status);
    if (params?.asset_id) q.append('asset_id', params.asset_id);
    if (params?.limit !== undefined) q.append('limit', String(params.limit));
    if (params?.offset !== undefined) q.append('offset', String(params.offset));
    const qs = q.toString();
    return fetchApi<{ predictions: PredictionRecord[]; total: number; limit: number; offset: number }>(
      qs ? `/adaptive/predictions?${qs}` : '/adaptive/predictions'
    );
  },
  getAdaptivePredictionDetail: (predictionId: string) =>
    fetchApi<PredictionRecord>(`/adaptive/predictions/${encodeURIComponent(predictionId)}`),
  getAdaptiveFeedback: () =>
    fetchApi<AdaptiveFeedbackInsights>('/adaptive/feedback'),
  getThreatIntelQuality: () =>
    fetchApi<ThreatIntelQualityMetrics>('/adaptive/threat-quality'),
  getShapOutcomeAnalysis: () =>
    fetchApi<any>('/adaptive/shap-analysis'),
  triggerTemporalEvaluation: (forceRecompute: boolean = false) =>
    fetchApi<any>('/adaptive/evaluate', {
      method: 'POST',
      body: JSON.stringify({ force_recompute: forceRecompute }),
    }),
  bootstrapAdaptiveBenchmark: () =>
    fetchApi<any>('/adaptive/bootstrap', {
      method: 'POST',
    }),
  syncAdaptiveGraph: () =>
    fetchApi<any>('/adaptive/sync-graph', {
      method: 'POST',
    }),

  // Phase 7.5: Adaptive Risk Calibration & Intelligent Threshold Optimization
  getCalibrationOverview: () =>
    fetchApi<CalibrationOverview>('/calibration/overview'),
  getCalibrationReport: () =>
    fetchApi<RiskScoreCalibrationReport>('/calibration/report'),
  optimizeThreshold: (minRecall: number = 0.90) =>
    fetchApi<CandidateOptimizationResult>(`/calibration/optimize?min_recall=${minRecall}`, {
      method: 'POST',
    }),
  runShadowEvaluation: (candidateThreshold: number, candidateConfigId?: string) =>
    fetchApi<ShadowEvaluationResult>('/calibration/shadow-evaluate', {
      method: 'POST',
      body: JSON.stringify({
        candidate_threshold: candidateThreshold,
        candidate_config_id: candidateConfigId,
      }),
    }),
  getAlertFatigueAnalytics: () =>
    fetchApi<AlertFatigueAnalytics>('/calibration/alert-fatigue'),
  getTelemetryDriftReport: () =>
    fetchApi<TelemetryDriftReport>('/calibration/drift'),
  getAdaptiveRecommendations: () =>
    fetchApi<AdaptiveRecommendation[]>('/calibration/recommendations'),
  listConfigurations: () =>
    fetchApi<ThresholdConfiguration[]>('/calibration/configurations'),
  getActiveConfiguration: () =>
    fetchApi<ThresholdConfiguration>('/calibration/configurations/active'),
  approveConfiguration: (configId: string) =>
    fetchApi<ThresholdConfiguration>(`/calibration/configurations/${encodeURIComponent(configId)}/approve`, {
      method: 'POST',
    }),
  rejectConfiguration: (configId: string, reason?: string) =>
    fetchApi<ThresholdConfiguration>(
      `/calibration/configurations/${encodeURIComponent(configId)}/reject${reason ? `?reason=${encodeURIComponent(reason)}` : ''}`,
      { method: 'POST' }
    ),
  activateConfiguration: (configId: string) =>
    fetchApi<ThresholdConfiguration>(`/calibration/configurations/${encodeURIComponent(configId)}/activate`, {
      method: 'POST',
    }),
  rollbackConfiguration: (targetConfigId: string, reason: string) =>
    fetchApi<ThresholdConfiguration>('/calibration/configurations/rollback', {
      method: 'POST',
      body: JSON.stringify({
        target_config_id: targetConfigId,
        reason: reason,
      }),
    }),

  // Phase 7.6: Predictive Threat Intelligence & Early-Warning Engine
  getEarlyWarningStatus: () =>
    fetchApi<EarlyWarningEngineStatus>('/early-warning/status'),
  getThreatSignals: (assetId?: string, severity?: string) => {
    const q = new URLSearchParams();
    if (assetId) q.append('asset_id', assetId);
    if (severity) q.append('severity', severity);
    const qs = q.toString();
    return fetchApi<ThreatSignal[]>(qs ? `/early-warning/signals?${qs}` : '/early-warning/signals');
  },
  getRiskTrajectory: (assetId: string, horizonHours: number = 6.0) =>
    fetchApi<RiskTrajectory>(`/early-warning/trajectories/${encodeURIComponent(assetId)}?horizon_hours=${horizonHours}`),
  getEscalationPredictions: (state?: string) => {
    const qs = state ? `?state=${encodeURIComponent(state)}` : '';
    return fetchApi<EscalationPrediction[]>(`/early-warning/escalations${qs}`);
  },
  getCorrelatedThreatClusters: (severity?: string) => {
    const qs = severity ? `?severity=${encodeURIComponent(severity)}` : '';
    return fetchApi<CorrelatedThreatCluster[]>(`/early-warning/clusters${qs}`);
  },
  getEarlyWarnings: (severity?: string, assetId?: string, status?: string) => {
    const q = new URLSearchParams();
    if (severity) q.append('severity', severity);
    if (assetId) q.append('asset_id', assetId);
    if (status) q.append('status', status);
    const qs = q.toString();
    return fetchApi<EarlyWarning[]>(qs ? `/early-warning/warnings?${qs}` : '/early-warning/warnings');
  },
  getWarningDetails: (warningId: string) =>
    fetchApi<EarlyWarning>(`/early-warning/warnings/${encodeURIComponent(warningId)}`),
  getWarningInvestigation: (warningId: string) =>
    fetchApi<InvestigationContext>(`/early-warning/warnings/${encodeURIComponent(warningId)}/investigation`),
  acknowledgeEarlyWarning: (warningId: string) =>
    fetchApi<EarlyWarning>(`/early-warning/warnings/${encodeURIComponent(warningId)}/acknowledge`, {
      method: 'POST',
    }),
  getPredictiveValidation: () =>
    fetchApi<PredictiveValidationMetric>('/early-warning/validation'),
  triggerEarlyWarningPipeline: () =>
    fetchApi<any>('/early-warning/evaluate', {
      method: 'POST',
    }),
  syncEarlyWarningGraph: () =>
    fetchApi<any>('/early-warning/sync', {
      method: 'POST',
    }),
};

export interface ThreatIndicator {
  id: string;
  type: string;
  value: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  source: string;
  first_seen: string;
  last_seen: string;
  associated_asset_ids: string[];
  associated_alert_ids: string[];
  associated_cves: string[];
  description: string;
  metadata: Record<string, any>;
}

export interface ThreatCorrelation {
  correlation_id: string;
  primary_indicator: ThreatIndicator;
  correlated_indicator: ThreatIndicator;
  correlation_score: number;
  confidence_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  correlation_reasons: string[];
  shared_assets: string[];
  shared_attack_paths: string[];
  scoring_breakdown: {
    indicator_match_score: number;
    graph_proximity_score: number;
    attack_path_relevance_score: number;
    freshness_reliability_score: number;
    total_composite_score: number;
  };
  ml_risk_context: Record<string, any>;
  detected_at: string;
}

export interface IncidentCluster {
  cluster_id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence_score: number;
  confidence_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  indicators: ThreatIndicator[];
  affected_assets: string[];
  crown_jewels_at_risk: string[];
  related_alert_ids: string[];
  attack_path_ids: string[];
  ml_assessment: {
    monitored_assets_count?: number;
    at_risk_assets_count?: number;
    max_ml_probability?: number;
    asset_assessments?: Record<string, any>;
    top_shap_drivers?: Record<string, string[]>;
  };
  cluster_explanation: string;
  created_at: string;
  updated_at: string;
  status: string;
}

export interface ThreatIntelSummary {
  total_indicators: number;
  indicators_by_type: Record<string, number>;
  indicators_by_severity: Record<string, number>;
  total_correlations: number;
  active_clusters_count: number;
  critical_clusters_count: number;
  compromised_assets_count: number;
  crown_jewels_at_risk_count: number;
  mean_correlation_confidence: number;
  highest_severity: string;
  sources_summary: Record<string, number>;
  last_correlated_at?: string;
}

export interface CSVIngestionSummary {
  upload_id: string;
  filename: string;
  csv_type: string;
  total_rows: number;
  accepted_rows: number;
  rejected_rows: number;
  duplicate_rows: number;
  nodes_created: number;
  nodes_updated: number;
  relationships_created: number;
  relationships_updated: number;
  neo4j_synced: boolean;
  neo4j_status: string;
  neo4j_details: Record<string, any>;
  validation_errors: Array<{
    row: number;
    entity_id?: string;
    field?: string;
    error: string;
  }>;
  status: string;
  message: string;
  is_sampled?: boolean;
  processing_duration_ms?: number;
  timestamp: string;
}

export interface ForecastHorizonMetadata {
  id: string;
  label: string;
  hours: number;
  description: string;
}

export interface ForecastFeatureContribution {
  feature_name: string;
  shap_value: number;
  feature_value: number;
  impact_direction: 'RISK_INCREASING' | 'RISK_DECREASING' | 'NEUTRAL';
  display_label: string;
}

export interface PropagationHop {
  hop_number: number;
  source_asset_id: string;
  source_asset_name: string;
  target_asset_id: string;
  target_asset_name: string;
  relationship_type: string;
  attenuated_risk_factor: number;
  is_crown_jewel: boolean;
}

export interface AssetRiskForecast {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  exposure_tier: string;
  is_crown_jewel: boolean;
  criticality: number;
  horizon: 'NEAR_TERM' | 'SHORT_TERM' | 'MEDIUM_TERM';
  horizon_hours: number;
  current_risk_score: number;
  predicted_future_risk_score: number;
  predicted_future_probability: number;
  risk_delta: number;
  risk_trend: 'ACCELERATING' | 'ELEVATED' | 'STABLE' | 'DECLINING';
  forecast_confidence: number;
  top_risk_drivers: ForecastFeatureContribution[];
  top_protective_factors: ForecastFeatureContribution[];
  propagation_depth: number;
  propagation_path: PropagationHop[];
  containment_urgency: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
  recommended_action: string;
  forecast_rationale: string;
}

export interface ForecastingSummary {
  horizon: 'NEAR_TERM' | 'SHORT_TERM' | 'MEDIUM_TERM';
  horizon_hours: number;
  total_assets_evaluated: number;
  high_risk_projected_count: number;
  accelerating_risk_count: number;
  crown_jewels_at_risk_count: number;
  mean_forecast_probability: number;
  top_projected_target: string;
  top_target_probability: number;
  operating_threshold: number;
  max_propagation_depth: number;
  model_auc_roc: number;
  generated_at: string;
}

export interface ForecastingEvaluationResult {
  horizon: string;
  sample_size: number;
  positive_label_count: number;
  cv_folds: number;
  gbdt_cv_roc_auc: number;
  static_baseline_roc_auc: number;
  auc_relative_improvement_pct: number;
  gbdt_cv_brier_score: number;
  static_baseline_brier_score: number;
  brier_error_reduction_pct: number;
  recall_at_calibrated_threshold: number;
  precision_at_calibrated_threshold: number;
  f1_at_calibrated_threshold: number;
  calibrated_threshold: number;
  methodology_notes: string;
  timestamp: string;
}

// =============================================================================
// PHASE 7.4: ADAPTIVE THREAT INTELLIGENCE & PREDICTIVE FEEDBACK LOOP
// =============================================================================

export type PredictionOutcomeStatus =
  | 'CONFIRMED_COMPROMISE'
  | 'FALSE_POSITIVE'
  | 'CORRECT_NON_EVENT'
  | 'FALSE_NEGATIVE'
  | 'PENDING_EVALUATION'
  | 'INSUFFICIENT_EVIDENCE';

export interface PredictionRecord {
  prediction_id: string;
  asset_id: string;
  asset_name: string;
  asset_type?: string;
  prediction_timestamp: string;
  forecast_horizon: string;
  horizon_hours: number;
  horizon_end_timestamp: string;
  predicted_probability: number;
  predicted_risk_score: number;
  predicted_threat_class: string;
  model_version: string;
  operating_threshold: number;
  threshold_crossed: boolean;
  top_features: Array<Record<string, any>>;
  propagation_depth: number;
  forecast_explanation?: string;
  outcome_status: PredictionOutcomeStatus;
  outcome_evaluation_timestamp?: string;
  actual_outcome?: string;
  outcome_source?: string;
  evidence_ids: string[];
  evaluation_notes?: string;
}

export interface HorizonComparisonItem {
  horizon: string;
  evaluated_count: number;
  precision: number | null;
  recall: number | null;
  f1_score: number | null;
  brier_score: number | null;
  accuracy: number | null;
  false_positive_rate: number | null;
}

export interface AssetTypePerformance {
  asset_type: string;
  sample_size: number;
  accuracy: number | null;
  precision: number | null;
  recall: number | null;
  f1_score: number | null;
  brier_score: number | null;
  false_positives: number;
  false_negatives: number;
}

export interface PredictivePerformanceMetrics {
  evaluated_count: number;
  pending_count: number;
  insufficient_evidence_count: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number | null;
  recall: number | null;
  f1_score: number | null;
  false_positive_rate: number | null;
  false_negative_rate: number | null;
  accuracy: number | null;
  brier_score: number | null;
  operating_threshold: number;
  confusion_matrix: number[][];
  horizon_breakdown?: HorizonComparisonItem[];
  asset_type_breakdown?: AssetTypePerformance[];
  evaluated_at?: string;
}

export interface AdaptiveFeedbackInsights {
  repeated_false_positives: Array<{
    asset_id: string;
    asset_name: string;
    asset_type?: string;
    false_positive_count: number;
    mean_predicted_probability: number;
    operating_threshold: number;
    top_associated_features: string[];
    recommended_mitigation: string;
  }>;
  repeated_false_negatives: Array<{
    asset_id: string;
    asset_name: string;
    asset_type?: string;
    false_negative_count: number;
    mean_predicted_probability: number;
    operating_threshold: number;
    observed_incident_count: number;
    recommended_mitigation: string;
  }>;
  weakest_horizon: string | null;
  strongest_horizon: string | null;
  weak_asset_types: string[];
  error_associated_features: Array<{
    feature_name: string;
    error_occurrences: number;
    mean_value_on_errors: number;
    insight: string;
  }>;
  threat_indicator_insights: Array<{
    indicator_id: string;
    indicator_value: string;
    source: string;
    confirmed_compromises: number;
    false_alarms: number;
    validity_assessment: string;
  }>;
  secops_governance_recommendations: string[];
  governance_note: string;
  generated_at: string;
}

export interface ThreatIntelQualityMetrics {
  total_evaluated_indicators: number;
  source_confirmation_rates: Record<string, number>;
  source_mean_confidences: Record<string, number>;
  multi_source_independence_rate: number;
  reliable_sources: string[];
  suspect_noisy_sources: string[];
  top_validated_indicators: Array<{
    indicator_id: string;
    value: string;
    type: string;
    source: string;
    confidence: number;
    confirmed_compromise_count: number;
    evidence_status: string;
  }>;
  evaluation_timestamp: string;
  quality_notes: string;
}

export interface AdaptiveSummary {
  total_predictions: number;
  evaluated_predictions: number;
  pending_predictions: number;
  insufficient_evidence_predictions: number;
  overall_precision: number | null;
  overall_recall: number | null;
  overall_f1: number | null;
  overall_brier_score: number | null;
  operating_threshold: number;
  data_quality_status: string;
  data_quality_notes: string;
  latest_evaluated_at?: string;
  active_model_version: string;
  generated_at: string;
}

// =============================================================================
// PHASE 7.5: ADAPTIVE RISK CALIBRATION & THRESHOLD OPTIMIZATION
// =============================================================================

export interface ReliabilityBin {
  bin_index: number;
  bin_range_low: number;
  bin_range_high: number;
  sample_count: number;
  mean_predicted_probability: number | null;
  empirical_threat_rate: number | null;
  calibration_error: number | null;
  bin_status: string;
}

export interface CategoryCalibrationBreakdown {
  category_name: string;
  sample_size: number;
  brier_score: number | null;
  expected_calibration_error: number | null;
  overprediction_rate: number | null;
  underprediction_rate: number | null;
  calibration_status: string;
  confidence: string;
}

export interface RiskScoreCalibrationReport {
  calibration_status: string;
  expected_calibration_error: number | null;
  brier_score: number | null;
  overprediction_rate: number | null;
  underprediction_rate: number | null;
  calibration_quality_score: number | null;
  sample_size: number;
  evaluated_threats_count: number;
  evaluated_benign_count: number;
  time_window_start?: string;
  time_window_end?: string;
  reliability_bins: ReliabilityBin[];
  asset_type_breakdowns: CategoryCalibrationBreakdown[];
  horizon_breakdowns: CategoryCalibrationBreakdown[];
  confidence: string;
  data_source: string;
  limitations: string[];
  generated_at: string;
}

export interface ThresholdTiers {
  low_cutoff: number;
  medium_cutoff: number;
  high_cutoff: number;
  critical_cutoff: number;
}

export interface ThresholdConfiguration {
  config_id: string;
  version: string;
  operating_threshold: number;
  tiers: ThresholdTiers;
  status: 'ACTIVE' | 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'SUPERSEDED' | 'ROLLED_BACK';
  author_id: string;
  author_role: string;
  rationale: string;
  supporting_evidence: Record<string, any>;
  parent_version?: string;
  approved_by?: string;
  approved_at?: string;
  activated_by?: string;
  activated_at?: string;
  created_at: string;
}

export interface CandidateOptimizationResult {
  status: string;
  baseline_threshold: number;
  recommended_threshold: number;
  optimization_objective: string;
  minimum_recall_constraint: number;
  critical_threat_weakened: boolean;
  candidate_configuration: ThresholdConfiguration;
  baseline_metrics: Record<string, any>;
  candidate_metrics: Record<string, any>;
  tradeoffs: Record<string, any>;
  confidence: string;
  rationale: string;
  generated_at: string;
}

export interface AssetClassificationFlip {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  is_crown_jewel: boolean;
  predicted_probability: number;
  baseline_classification: string;
  candidate_classification: string;
  actual_outcome: string;
  impact_description: string;
}

export interface ShadowEvaluationResult {
  evaluation_id: string;
  baseline_config_id: string;
  candidate_config_id: string;
  evaluated_sample_size: number;
  baseline_threshold: number;
  candidate_threshold: number;
  baseline_alert_count: number;
  candidate_alert_count: number;
  alert_volume_delta: number;
  alert_volume_percent_change: number;
  baseline_false_positives: number;
  candidate_false_positives: number;
  false_positive_delta: number;
  baseline_false_negatives: number;
  candidate_false_negatives: number;
  false_negative_delta: number;
  baseline_precision: number | null;
  candidate_precision: number | null;
  baseline_recall: number | null;
  candidate_recall: number | null;
  baseline_f1: number | null;
  candidate_f1: number | null;
  critical_threats_retained: boolean;
  critical_threat_miss_count: number;
  classification_flips_count: number;
  flipped_assets: AssetClassificationFlip[];
  tradeoff_summary: string;
  recommendation: string;
  evaluated_at: string;
}

export interface NoisyAssetItem {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  total_alerts: number;
  false_positive_count: number;
  confirmed_breach_count: number;
  false_alarm_rate: number;
  primary_alert_driver: string;
  recommended_mitigation: string;
}

export interface AlertFatigueAnalytics {
  total_alerts_analyzed: number;
  mean_alerts_per_asset: number;
  max_alerts_single_asset: number;
  gini_alert_concentration: number;
  alert_fatigue_index: number;
  total_false_positives: number;
  total_confirmed_threats: number;
  overall_false_alarm_ratio: number;
  noisy_assets: NoisyAssetItem[];
  severity_distribution: Record<string, number>;
  fatigue_status: string;
  governance_advisory: string;
  analyzed_at: string;
}

export interface FeatureDriftItem {
  feature_name: string;
  psi_score: number;
  ks_statistic?: number | null;
  drift_status: string;
  baseline_mean: number;
  current_mean: number;
  delta_percent: number;
}

export interface TelemetryDriftReport {
  drift_detected: boolean;
  overall_drift_severity: string;
  risk_score_wasserstein_distance: number;
  calibration_degradation_detected: boolean;
  baseline_brier_score?: number | null;
  current_brier_score?: number | null;
  sensor_coverage_gap_count: number;
  evaluated_sample_size: number;
  feature_drift_breakdown: FeatureDriftItem[];
  confidence: string;
  baseline_window: string;
  current_window: string;
  explanation: string;
  recommended_action: string;
  evaluated_at: string;
}

export interface AdaptiveRecommendation {
  recommendation_id: string;
  title: string;
  category: string;
  severity: string;
  explanation: string;
  supporting_evidence: Record<string, any>;
  sample_size: number;
  confidence_level: string;
  proposed_change: string;
  expected_benefit: string;
  potential_risk: string;
  alternative_options: string[];
  required_approval_role: string;
  status: string;
  created_at: string;
}

export interface CalibrationOverview {
  active_version: string;
  active_threshold: number;
  calibration_status: string;
  calibration_quality_score?: number | null;
  expected_calibration_error?: number | null;
  brier_score?: number | null;
  alert_fatigue_index: number;
  fatigue_status: string;
  drift_detected: boolean;
  drift_severity: string;
  total_evaluated_samples: number;
  pending_recommendations_count: number;
}

// =============================================================================
// Phase 7.6: Predictive Threat Intelligence & Early-Warning Interfaces
// =============================================================================

export interface ThreatSignal {
  signal_id: string;
  asset_id: string;
  signal_type: string;
  severity: string;
  observed_value: number;
  baseline_value?: number | null;
  deviation?: number | null;
  timestamp: string;
  source: string;
  evidence: string;
  confidence: number;
  related_entities: string[];
}

export interface RiskTrajectoryPoint {
  timestamp: string;
  risk_score?: number | null;
}

export interface RiskTrajectory {
  asset_id: string;
  slope: number;
  acceleration: number;
  volatility: number;
  moving_average_risk: number;
  ema_risk: number;
  current_risk: number;
  projected_risk: number;
  trajectory_direction: string;
  cusum_changepoint_detected: boolean;
  data_sufficiency: string;
  sample_size: number;
  forecast_horizon_hours: number;
  projection_confidence: number;
  evaluated_at: string;
  historical_values: RiskTrajectoryPoint[];
  bounded_projections: RiskTrajectoryPoint[];
  formula_expression?: string | null;
}

export interface EscalationPrediction {
  prediction_id: string;
  asset_id: string;
  current_state: string;
  predicted_state: string;
  escalation_risk_score: number;
  escalation_probability: number;
  confidence: number;
  evidence: string[];
  is_crown_jewel: boolean;
  is_verified_threat: boolean;
  invariant_applied: boolean;
  prediction_horizon_hours: number;
  generated_at: string;
}

export interface CorrelatedThreatCluster {
  cluster_id: string;
  cluster_name: string;
  primary_pattern: string;
  severity: string;
  confidence: number;
  related_asset_ids: string[];
  crown_jewels_at_risk: string[];
  signals: ThreatSignal[];
  attack_path_ids: string[];
  graph_evidence: string[];
  recommended_containment_posture: string;
  detected_at: string;
}

export interface EarlyWarning {
  warning_id: string;
  asset_id: string;
  affected_entities: string[];
  warning_type: string;
  severity: string;
  priority_score: number;
  status: string;
  generated_at: string;
  acknowledged_at?: string | null;
  resolved_at?: string | null;
  acknowledged_by?: string | null;
  observed_evidence: string[];
  explanation: string;
  confidence: number;
  predicted_impact: string;
  recommended_action: string;
  contributing_signals: string[];
  cooldown_until?: string | null;
}

export interface InvestigationContext {
  investigation_id: string;
  warning_id: string;
  asset_id: string;
  asset_name: string;
  what_happened: string;
  what_was_observed: string;
  what_changed: string;
  why_it_matters: string;
  related_assets: string[];
  relevant_graph_relationships: string[];
  risk_trajectory_evolution: string;
  potential_escalation: string;
  supporting_evidence: string[];
  uncertainty_factors: string[];
  recommended_investigation_steps: string[];
  generated_at: string;
}

export interface EarlyWarningEngineStatus {
  engine_version: string;
  is_shadow_mode: boolean;
  active_warnings_count: number;
  critical_warnings_count: number;
  escalating_assets_count: number;
  extracted_signals_count: number;
  threat_clusters_count: number;
  graph_persistence_backend: string;
  neo4j_live: boolean;
  production_config_protected: boolean;
  active_threshold: number;
  timestamp: string;
}

export interface PredictiveValidationMetric {
  total_predictions_evaluated: number;
  confirmed_escalations: number;
  false_warnings: number;
  missed_escalations: number;
  accuracy: number;
  precision: number;
  recall: number;
  brier_score: number;
  mean_lead_time_hours: number;
  median_lead_time_hours: number;
  max_lead_time_hours: number;
  min_lead_time_hours: number;
  lead_time_distribution: Record<string, number>;
  data_leakage_prevented: boolean;
  evaluated_at: string;
}

