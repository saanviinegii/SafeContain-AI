/**
 * SafeContain AI Frontend REST API Client.
 * Connects directly to FastAPI backend /api/v1/ endpoints.
 */

const API_BASE = '/api/v1';

export async function fetchApi<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
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
  runSimulation: () => fetchApi<any>('/simulation/run', { method: 'POST' }),
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
  exportReport: (format: 'json' | 'csv' | 'text') => fetchApi<any>(`/reports/export?format=${format}`),
};
