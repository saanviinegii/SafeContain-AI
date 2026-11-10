/**
 * SafeContain AI Frontend REST API Client.
 * Connects directly to FastAPI backend /api/v1/ endpoints.
 * Automatically resolves endpoint URL across local dev, static preview, and unified cloud production.
 */

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
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`API Error [${response.status}] ${response.statusText}: ${errorBody}`);
  }

  return response.json();
}

export const api = {
  getHealth: () => fetchApi<any>('/health'),
  getMetrics: () => fetchApi<any>('/metrics'),
  loadSyntheticScenario: (name?: string) =>
    fetchApi<any>(`/scenario/load-synthetic${name ? `?scenario_name=${encodeURIComponent(name)}` : ''}`, { method: 'POST' }),
  getTopology: () => fetchApi<{ nodes: any[]; edges: any[]; backend: string }>('/graph/topology'),
  getNeo4jStatus: () => fetchApi<any>('/graph/neo4j/status'),
  syncNeo4j: () => fetchApi<any>('/graph/neo4j/sync', { method: 'POST' }),
  loadFromNeo4j: () => fetchApi<any>('/graph/neo4j/load', { method: 'POST' }),
  getAttackPaths: () => fetchApi<any[]>('/graph/attack-paths'),
  getEvidenceSensitivity: () => fetchApi<any[]>('/evidence/sensitivity'),
  getDecomposedRisk: () => fetchApi<any>('/risk/decompose'),
  getWorkflows: () => fetchApi<any[]>('/business/workflows'),
  getCandidateActions: () => fetchApi<any[]>('/planning/candidates'),
  optimizeContainment: (budgetLimit: number, strategy: string) =>
    fetchApi<any>('/planning/optimize', {
      method: 'POST',
      body: JSON.stringify({ budget_limit: budgetLimit, strategy }),
    }),
  runSimulation: (req?: { action_ids?: string[]; strategy?: string; budget_limit?: number }) =>
    fetchApi<any>('/simulation/run', {
      method: 'POST',
      body: req ? JSON.stringify(req) : undefined,
    }),
  getExplanation: () => fetchApi<any>('/explanation/recommendation'),
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
  getAuditLedger: (limit = 50) => fetchApi<any[]>(`/audit/ledger?limit=${limit}`),
  verifyAuditIntegrity: () => fetchApi<any>('/audit/verify'),
  getBlockchainStatus: () => fetchApi<any>('/audit/blockchain/status'),
  getBlockchainRecords: () => fetchApi<any[]>('/audit/blockchain/records'),
  verifyBlockchainRecord: (eventId: string) =>
    fetchApi<any>(`/audit/blockchain/verify?event_id=${encodeURIComponent(eventId)}`, { method: 'POST' }),
  exportReport: (format: 'json' | 'csv' | 'text') => fetchApi<any>(`/reports/export?format=${format}`),
};
