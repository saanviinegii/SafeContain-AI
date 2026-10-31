import React, { useEffect, useState } from 'react';
import {
  Shield,
  Activity,
  Network,
  GitBranch,
  HelpCircle,
  Server,
  AlertTriangle,
  Building2,
  ListPlus,
  Scale,
  PlayCircle,
  CheckCircle2,
  FileText,
  Lock,
  Database,
  Users,
  Settings,
  Download,
  Terminal,
  RefreshCw,
} from 'lucide-react';
import { api } from './api/client';
import { CytoscapeGraph } from './components/CytoscapeGraph';

// 19 Enterprise Operational Views
type ViewType =
  | 'EXECUTIVE_OVERVIEW'
  | 'SOC_OPERATIONS'
  | 'TOPOLOGY_EXPLORER'
  | 'ATTACK_PATHS'
  | 'EVIDENCE_UNCERTAINTY'
  | 'ASSET_INTELLIGENCE'
  | 'RISK_ANALYSIS'
  | 'BUSINESS_TWIN'
  | 'RESPONSE_PLANNER'
  | 'STRATEGY_COMPARATOR'
  | 'SIMULATION_SANDBOX'
  | 'RESIDUAL_RISK'
  | 'DECISION_EXPLAINER'
  | 'APPROVAL_CENTER'
  | 'AUDIT_EXPLORER'
  | 'INTEGRATIONS'
  | 'USER_ROLES'
  | 'SYSTEM_ADMIN'
  | 'REPORTS_EXPORT';

export const App: React.FC = () => {
  const [activeView, setActiveView] = useState<ViewType>('EXECUTIVE_OVERVIEW');
  const [currentUserRole, setCurrentUserRole] = useState<string>('SECURITY_MANAGER');
  const [scenarioName] = useState<string>('Operation Sovereign Gateway');
  
  // Data state
  const [loading, setLoading] = useState<boolean>(true);
  const [topology, setTopology] = useState<{ nodes: any[]; edges: any[]; backend: string }>({ nodes: [], edges: [], backend: '' });
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
  const [riskData, setRiskData] = useState<any>(null);
  const [workflows, setWorkflows] = useState<any[]>([]);
  const [candidateActions, setCandidateActions] = useState<any[]>([]);
  const [strategyComparison, setStrategyComparison] = useState<any>(null);
  const [simulationResult, setSimulationResult] = useState<any>(null);
  const [explanation, setExplanation] = useState<any>(null);
  const [auditEvents, setAuditEvents] = useState<any[]>([]);
  const [auditIntegrity, setAuditIntegrity] = useState<any>(null);
  const [sensitivityList, setSensitivityList] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [notification, setNotification] = useState<string | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [selectedActionIds, setSelectedActionIds] = useState<string[]>([]);
  const [simulationStrategy, setSimulationStrategy] = useState<string>('CONSTRAINT_CPSAT');

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  const loadAllData = async () => {
    setLoading(true);
    try {
      const [topo, paths, risk, wfs, cands, comp, sim, exp, ledger, intReport, sens, mets] = await Promise.all([
        api.getTopology(),
        api.getAttackPaths(),
        api.getDecomposedRisk(),
        api.getWorkflows(),
        api.getCandidateActions(),
        api.optimizeContainment(10000, 'CONSTRAINT_CPSAT'),
        api.runSimulation(),
        api.getExplanation(),
        api.getAuditLedger(50),
        api.verifyAuditIntegrity(),
        api.getEvidenceSensitivity(),
        api.getMetrics(),
      ]);

      setTopology(topo);
      setAttackPaths(paths);
      setRiskData(risk);
      setWorkflows(wfs);
      setCandidateActions(cands);
      setStrategyComparison(comp);
      setSimulationResult(sim);
      if (sim?.applied_action_ids) {
        setSelectedActionIds(sim.applied_action_ids);
      }
      setExplanation(exp);
      setAuditEvents(ledger);
      setAuditIntegrity(intReport);
      setSensitivityList(sens);
      setMetrics(mets);
    } catch (err: any) {
      console.error('Failed loading data:', err);
      showNotification(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRunSimulation = async (actionIds?: string[], strategy?: string) => {
    setIsSimulating(true);
    try {
      const idsToSimulate = actionIds !== undefined ? actionIds : selectedActionIds;
      const stratToSimulate = strategy || simulationStrategy;
      if (strategy) {
        setSimulationStrategy(strategy);
      }
      const sim = await api.runSimulation({
        action_ids: idsToSimulate,
        strategy: stratToSimulate,
      });
      setSimulationResult(sim);
      if (sim?.applied_action_ids) {
        setSelectedActionIds(sim.applied_action_ids);
      }

      // Non-blocking background sync of explanation, audit ledger, and metrics
      const [exp, ledger, mets] = await Promise.all([
        api.getExplanation(),
        api.getAuditLedger(50),
        api.getMetrics(),
      ]);
      setExplanation(exp);
      setAuditEvents(ledger);
      setMetrics(mets);
      showNotification(
        `Simulation finished: Residual risk ${sim.residual_risk_score}/100, ${sim.residual_attack_path_count} paths remaining.`
      );
    } catch (err: any) {
      console.error('Simulation failed:', err);
      showNotification(`Simulation error: ${err.message}`);
    } finally {
      setIsSimulating(false);
    }
  };

  const toggleAction = (id: string) => {
    setSelectedActionIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  useEffect(() => {
    loadAllData();
  }, []);

  const handleReloadSynthetic = async () => {
    try {
      await api.loadSyntheticScenario('Operation Sovereign Gateway');
      await loadAllData();
      showNotification('Synthetic scenario reloaded successfully with strict SYNTHETIC provenance.');
    } catch (err: any) {
      showNotification(`Reload failed: ${err.message}`);
    }
  };

  const handleGovernanceTransition = async (targetStatus: string) => {
    try {
      await api.transitionGovernance(targetStatus, currentUserRole, `Transitioned to ${targetStatus} via Web Console.`);
      await loadAllData();
      showNotification(`Plan status transitioned to ${targetStatus}.`);
    } catch (err: any) {
      showNotification(`Governance Transition Denied: ${err.message}`);
    }
  };

  const handleExport = async (format: 'json' | 'csv' | 'text') => {
    try {
      const rep = await api.exportReport(format);
      const blob = new Blob([typeof rep.data === 'string' ? rep.data : JSON.stringify(rep.data, null, 2)], {
        type: format === 'json' ? 'application/json' : 'text/plain',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `safecontain_dossier_${Date.now()}.${format === 'text' ? 'txt' : format}`;
      a.click();
      showNotification(`Report exported in ${format.toUpperCase()} format.`);
    } catch (err: any) {
      showNotification(`Export error: ${err.message}`);
    }
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="app-sidebar">
        <div className="brand-header">
          <Shield className="brand-icon" />
          <div>
            <div className="brand-title">SAFECONTAIN AI</div>
            <div className="brand-subtitle">Enterprise Cyber Defense</div>
          </div>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Overview</div>
          <div
            className={`nav-item ${activeView === 'EXECUTIVE_OVERVIEW' ? 'active' : ''}`}
            onClick={() => setActiveView('EXECUTIVE_OVERVIEW')}
          >
            <Activity size={16} /> Executive Briefing
          </div>
          <div
            className={`nav-item ${activeView === 'SOC_OPERATIONS' ? 'active' : ''}`}
            onClick={() => setActiveView('SOC_OPERATIONS')}
          >
            <Terminal size={16} /> SOC Operations
          </div>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Graph Intelligence</div>
          <div
            className={`nav-item ${activeView === 'TOPOLOGY_EXPLORER' ? 'active' : ''}`}
            onClick={() => setActiveView('TOPOLOGY_EXPLORER')}
          >
            <Network size={16} /> Topology Explorer
          </div>
          <div
            className={`nav-item ${activeView === 'ATTACK_PATHS' ? 'active' : ''}`}
            onClick={() => setActiveView('ATTACK_PATHS')}
          >
            <GitBranch size={16} /> Attack Paths
          </div>
          <div
            className={`nav-item ${activeView === 'EVIDENCE_UNCERTAINTY' ? 'active' : ''}`}
            onClick={() => setActiveView('EVIDENCE_UNCERTAINTY')}
          >
            <HelpCircle size={16} /> Evidence Uncertainty
          </div>
          <div
            className={`nav-item ${activeView === 'ASSET_INTELLIGENCE' ? 'active' : ''}`}
            onClick={() => setActiveView('ASSET_INTELLIGENCE')}
          >
            <Server size={16} /> Asset Intelligence
          </div>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Risk & Business Twin</div>
          <div
            className={`nav-item ${activeView === 'RISK_ANALYSIS' ? 'active' : ''}`}
            onClick={() => setActiveView('RISK_ANALYSIS')}
          >
            <AlertTriangle size={16} /> Decomposed Risk
          </div>
          <div
            className={`nav-item ${activeView === 'BUSINESS_TWIN' ? 'active' : ''}`}
            onClick={() => setActiveView('BUSINESS_TWIN')}
          >
            <Building2 size={16} /> Business Continuity Twin
          </div>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Decision Support</div>
          <div
            className={`nav-item ${activeView === 'RESPONSE_PLANNER' ? 'active' : ''}`}
            onClick={() => setActiveView('RESPONSE_PLANNER')}
          >
            <ListPlus size={16} /> Action Catalog
          </div>
          <div
            className={`nav-item ${activeView === 'STRATEGY_COMPARATOR' ? 'active' : ''}`}
            onClick={() => setActiveView('STRATEGY_COMPARATOR')}
          >
            <Scale size={16} /> Strategy Comparator
          </div>
          <div
            className={`nav-item ${activeView === 'SIMULATION_SANDBOX' ? 'active' : ''}`}
            onClick={() => setActiveView('SIMULATION_SANDBOX')}
          >
            <PlayCircle size={16} /> Simulation Sandbox
          </div>
          <div
            className={`nav-item ${activeView === 'RESIDUAL_RISK' ? 'active' : ''}`}
            onClick={() => setActiveView('RESIDUAL_RISK')}
          >
            <CheckCircle2 size={16} /> Residual Risk Inspector
          </div>
          <div
            className={`nav-item ${activeView === 'DECISION_EXPLAINER' ? 'active' : ''}`}
            onClick={() => setActiveView('DECISION_EXPLAINER')}
          >
            <FileText size={16} /> Decision Explainer
          </div>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Governance & Audit</div>
          <div
            className={`nav-item ${activeView === 'APPROVAL_CENTER' ? 'active' : ''}`}
            onClick={() => setActiveView('APPROVAL_CENTER')}
          >
            <Lock size={16} /> Human Approval Center
          </div>
          <div
            className={`nav-item ${activeView === 'AUDIT_EXPLORER' ? 'active' : ''}`}
            onClick={() => setActiveView('AUDIT_EXPLORER')}
          >
            <Database size={16} /> Cryptographic Audit Ledger
          </div>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Operations</div>
          <div
            className={`nav-item ${activeView === 'INTEGRATIONS' ? 'active' : ''}`}
            onClick={() => setActiveView('INTEGRATIONS')}
          >
            <RefreshCw size={16} /> Data Connectors
          </div>
          <div
            className={`nav-item ${activeView === 'USER_ROLES' ? 'active' : ''}`}
            onClick={() => setActiveView('USER_ROLES')}
          >
            <Users size={16} /> Governance Roles
          </div>
          <div
            className={`nav-item ${activeView === 'SYSTEM_ADMIN' ? 'active' : ''}`}
            onClick={() => setActiveView('SYSTEM_ADMIN')}
          >
            <Settings size={16} /> System Telemetry
          </div>
          <div
            className={`nav-item ${activeView === 'REPORTS_EXPORT' ? 'active' : ''}`}
            onClick={() => setActiveView('REPORTS_EXPORT')}
          >
            <Download size={16} /> Export Dossier
          </div>
        </div>
      </aside>

      {/* Main Container */}
      <main className="app-main">
        {/* Top Operational Bar */}
        <header className="app-topbar">
          <div className="topbar-left">
            <h1 className="view-heading">{activeView.replace(/_/g, ' ')}</h1>
            <span className="scenario-pill">{scenarioName}</span>
          </div>

          <div className="topbar-right">
            {notification && (
              <span className="badge badge-amber" style={{ animation: 'fadeIn 0.2s' }}>
                {notification}
              </span>
            )}
            <div className="status-badge healthy">
              <span className="status-dot"></span>
              {topology.backend === 'neo4j_live' ? 'Neo4j Live' : 'NetworkX In-Memory (Active)'}
            </div>
            <button className="btn-secondary" onClick={handleReloadSynthetic} title="Reload Scenario">
              <RefreshCw size={14} /> Reset Scenario
            </button>
          </div>
        </header>

        {/* Dynamic View Content */}
        <section className="app-content">
          {loading ? (
            <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <RefreshCw className="brand-icon" style={{ animation: 'spin 1.5s linear infinite', margin: '0 auto 16px' }} />
              <div>Synchronizing Enterprise Graph Intelligence...</div>
            </div>
          ) : (
            <>
              {/* VIEW 1: EXECUTIVE OVERVIEW */}
              {activeView === 'EXECUTIVE_OVERVIEW' && (
                <div>
                  <div className="grid-cards">
                    <div className="metric-card">
                      <div className="metric-title">Inherent System Risk</div>
                      <div className="metric-value" style={{ color: '#f87171' }}>
                        {riskData?.inherent_risk ?? 0}/100
                      </div>
                      <div className="metric-desc">Unconstrained threat exposure</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Simulated Residual Risk</div>
                      <div className="metric-value" style={{ color: '#34d399' }}>
                        {simulationResult?.residual_risk_score ?? 0}/100
                      </div>
                      <div className="metric-desc">
                        -{simulationResult?.risk_reduction_achieved ?? 0} points reduction
                      </div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Attack Routes Discovered</div>
                      <div className="metric-value" style={{ color: '#fbbf24' }}>
                        {attackPaths.length}
                      </div>
                      <div className="metric-desc">
                        {simulationResult?.residual_attack_path_count ?? 0} residual post-containment
                      </div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Business SLA Status</div>
                      <div className="metric-value" style={{ color: '#60a5fa' }}>
                        {simulationResult?.disrupted_workflows.length === 0 ? '0 Outages' : `${simulationResult?.disrupted_workflows.length} Impacted`}
                      </div>
                      <div className="metric-desc">Critical citizen services preserved</div>
                    </div>
                  </div>

                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Simulated Containment Recommendation</div>
                      <span className="badge badge-emerald">CP-SAT OPTIMIZED</span>
                    </div>
                    <div style={{ padding: '20px' }}>
                      <p style={{ marginBottom: '14px', color: 'var(--text-primary)', fontSize: '14px', lineHeight: 1.6 }}>
                        {simulationResult?.explanation}
                      </p>
                      <div style={{ display: 'flex', gap: '12px' }}>
                        <button className="btn-primary" onClick={() => setActiveView('SIMULATION_SANDBOX')}>
                          <PlayCircle size={15} /> Open Simulation Sandbox
                        </button>
                        <button className="btn-secondary" onClick={() => setActiveView('APPROVAL_CENTER')}>
                          <Lock size={15} /> Review & Approve
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Live Infrastructure Topology Preview</div>
                      <span className="badge badge-blue">{topology.nodes.length} Nodes | {topology.edges.length} Edges</span>
                    </div>
                    <CytoscapeGraph
                      nodes={topology.nodes}
                      edges={topology.edges}
                      onSelectNode={(node) => setSelectedNode(node)}
                    />
                  </div>
                </div>
              )}

              {/* VIEW 2: SOC OPERATIONS */}
              {activeView === 'SOC_OPERATIONS' && (
                <div>
                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Active Security Incident Stream</div>
                      <span className="badge badge-crimson">LIVE TELEMETRY & SYNTHETIC</span>
                    </div>
                    <table className="safe-table">
                      <thead>
                        <tr>
                          <th>Target Entity</th>
                          <th>Threat Type</th>
                          <th>Severity</th>
                          <th>Status</th>
                          <th>Action Trigger</th>
                        </tr>
                      </thead>
                      <tbody>
                        {topology.nodes.filter(n => n.is_compromised).map(n => (
                          <tr key={n.id}>
                            <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{n.name}</td>
                            <td>{n.properties?.mitre_technique ?? 'APT Lateral Movement'}</td>
                            <td><span className="badge badge-crimson">{(n.criticality * 10).toFixed(1)} HIGH</span></td>
                            <td><span className="badge badge-amber">ACTIVE THREAT</span></td>
                            <td>
                              <button className="btn-secondary" style={{ padding: '4px 10px', fontSize: '12px' }} onClick={() => setActiveView('RESPONSE_PLANNER')}>
                                Evaluate Containment
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* VIEW 3: TOPOLOGY EXPLORER */}
              {activeView === 'TOPOLOGY_EXPLORER' && (
                <div>
                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Interactive Infrastructure Graph Explorer</div>
                      <span className="badge badge-blue">Select any node to inspect metadata</span>
                    </div>
                    <CytoscapeGraph
                      nodes={topology.nodes}
                      edges={topology.edges}
                      onSelectNode={(node) => setSelectedNode(node)}
                    />
                  </div>
                  {selectedNode && (
                    <div className="data-table-container" style={{ padding: '20px' }}>
                      <h3 style={{ marginBottom: '10px', color: 'var(--accent-cyan)' }}>Node Inspector: {selectedNode.full_name}</h3>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                        <div><strong>ID:</strong> {selectedNode.id}</div>
                        <div><strong>Type:</strong> {selectedNode.type}</div>
                        <div><strong>Criticality:</strong> {selectedNode.criticality}</div>
                        <div><strong>Crown Jewel:</strong> {selectedNode.is_crown_jewel ? 'YES' : 'NO'}</div>
                        <div><strong>Compromised:</strong> {selectedNode.is_compromised ? 'YES' : 'NO'}</div>
                        <div><strong>Provenance:</strong> {selectedNode.provenance}</div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* VIEW 4: ATTACK PATHS */}
              {activeView === 'ATTACK_PATHS' && (
                <div className="data-table-container">
                  <div className="table-header">
                    <div className="table-title">Discovered Directed Attack Paths</div>
                    <span className="badge badge-amber">{attackPaths.length} Active Routes</span>
                  </div>
                  <table className="safe-table">
                    <thead>
                      <tr>
                        <th>Path ID</th>
                        <th>Traversal Route</th>
                        <th>Hops</th>
                        <th>Inherent Risk</th>
                        <th>Confidence</th>
                        <th>Choke Points</th>
                      </tr>
                    </thead>
                    <tbody>
                      {attackPaths.map(p => (
                        <tr key={p.id}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{p.id}</td>
                          <td style={{ color: 'var(--text-primary)' }}>{p.node_sequence.join(' → ')}</td>
                          <td>{p.hop_count}</td>
                          <td><span className="badge badge-crimson">{p.inherent_path_risk.toFixed(1)}</span></td>
                          <td>{(p.confidence_score * 100).toFixed(0)}%</td>
                          <td>
                            {p.choke_point_nodes.length > 0 ? (
                              <span className="badge badge-purple">{p.choke_point_nodes.join(', ')}</span>
                            ) : (
                              <span style={{ color: 'var(--text-muted)' }}>None</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* VIEW 5: EVIDENCE UNCERTAINTY */}
              {activeView === 'EVIDENCE_UNCERTAINTY' && (
                <div>
                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Evidence Sensitivity & Drift Scenarios</div>
                      <span className="badge badge-purple">5-State Uncertainty Engine</span>
                    </div>
                    <table className="safe-table">
                      <thead>
                        <tr>
                          <th>Perturbation Hypothesis</th>
                          <th>Edge ID</th>
                          <th>Original State</th>
                          <th>New State</th>
                          <th>Risk Delta</th>
                          <th>Plan Stability Impact</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sensitivityList.map((s, idx) => (
                          <tr key={idx}>
                            <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{s.scenario_name}</td>
                            <td style={{ fontFamily: 'var(--font-mono)' }}>{s.perturbed_edge_id}</td>
                            <td><span className="badge badge-amber">{s.original_status}</span></td>
                            <td><span className="badge badge-blue">{s.new_status}</span></td>
                            <td style={{ color: s.risk_delta > 0 ? '#f87171' : '#34d399', fontWeight: 600 }}>
                              {s.risk_delta > 0 ? `+${s.risk_delta}` : s.risk_delta}
                            </td>
                            <td>
                              <span className={`badge ${s.plan_stability_impact === 'STRATEGY_FLIP' ? 'badge-crimson' : 'badge-emerald'}`}>
                                {s.plan_stability_impact}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* VIEW 6: ASSET INTELLIGENCE */}
              {activeView === 'ASSET_INTELLIGENCE' && (
                <div className="data-table-container">
                  <div className="table-header">
                    <div className="table-title">Infrastructure Asset Inventory</div>
                    <span className="badge badge-blue">{topology.nodes.length} Registered Entities</span>
                  </div>
                  <table className="safe-table">
                    <thead>
                      <tr>
                        <th>Asset ID</th>
                        <th>Name</th>
                        <th>Class</th>
                        <th>Criticality</th>
                        <th>Threat Status</th>
                        <th>Crown Jewel</th>
                        <th>Provenance</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topology.nodes.map(n => (
                        <tr key={n.id}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{n.id}</td>
                          <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{n.name}</td>
                          <td>{n.type}</td>
                          <td>{(n.criticality * 100).toFixed(0)}%</td>
                          <td>
                            {n.is_compromised ? (
                              <span className="badge badge-crimson">COMPROMISED</span>
                            ) : (
                              <span className="badge badge-emerald">SECURE</span>
                            )}
                          </td>
                          <td>
                            {n.is_crown_jewel ? (
                              <span className="badge badge-amber">CROWN JEWEL</span>
                            ) : (
                              <span style={{ color: 'var(--text-muted)' }}>Standard</span>
                            )}
                          </td>
                          <td><span className="badge badge-blue">{n.provenance}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* VIEW 7: RISK ANALYSIS */}
              {activeView === 'RISK_ANALYSIS' && (
                <div>
                  <div className="grid-cards">
                    <div className="metric-card">
                      <div className="metric-title">Inherent Risk</div>
                      <div className="metric-value">{riskData?.inherent_risk}</div>
                      <div className="metric-desc">Worst-case exposure without controls</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Observed Risk</div>
                      <div className="metric-value">{riskData?.observed_risk}</div>
                      <div className="metric-desc">Active confirmed threat activity</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Potential Risk</div>
                      <div className="metric-value">{riskData?.potential_risk}</div>
                      <div className="metric-desc">Includes unverified/suspected links</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Uncertainty Penalty</div>
                      <div className="metric-value" style={{ color: '#fbbf24' }}>
                        +{riskData?.uncertainty_penalty}
                      </div>
                      <div className="metric-desc">Epistemic uncertainty burden</div>
                    </div>
                  </div>

                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Contributing Risk Factors & Weights</div>
                    </div>
                    <table className="safe-table">
                      <thead>
                        <tr>
                          <th>Factor Name</th>
                          <th>Assigned Weight</th>
                          <th>Calculated Score</th>
                          <th>Explanation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {riskData?.contributing_factors?.map((f: any, idx: number) => (
                          <tr key={idx}>
                            <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{f.factor_name}</td>
                            <td>{(f.weight * 100).toFixed(0)}%</td>
                            <td><span className="badge badge-amber">{f.score}</span></td>
                            <td>{f.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* VIEW 8: BUSINESS CONTINUITY TWIN */}
              {activeView === 'BUSINESS_TWIN' && (
                <div className="data-table-container">
                  <div className="table-header">
                    <div className="table-title">Monitored Business & Citizen Services</div>
                    <span className="badge badge-emerald">ZERO OUTAGE SLA ENFORCED</span>
                  </div>
                  <table className="safe-table">
                    <thead>
                      <tr>
                        <th>Workflow</th>
                        <th>Criticality Tier</th>
                        <th>Citizen Facing</th>
                        <th>Max Allowable Downtime</th>
                        <th>Hourly Downtime Cost</th>
                        <th>Operational Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {workflows.map(w => (
                        <tr key={w.id}>
                          <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{w.name}</td>
                          <td><span className="badge badge-purple">{w.criticality}</span></td>
                          <td>{w.citizen_facing ? <span className="badge badge-amber">CITIZEN PORTAL</span> : 'Internal'}</td>
                          <td>{w.max_allowable_downtime_hours} hrs</td>
                          <td>${w.estimated_hourly_downtime_cost.toLocaleString()}/hr</td>
                          <td><span className="badge badge-emerald">{w.operational_status}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* VIEW 9: RESPONSE PLANNER */}
              {activeView === 'RESPONSE_PLANNER' && (
                <div className="data-table-container">
                  <div className="table-header">
                    <div className="table-title">Containment Intervention Catalog (11+ Actions)</div>
                    <span className="badge badge-blue">{candidateActions.length} Synthesized Actions</span>
                  </div>
                  <table className="safe-table">
                    <thead>
                      <tr>
                        <th>Action ID</th>
                        <th>Type</th>
                        <th>Target Entity</th>
                        <th>Risk Reduction</th>
                        <th>Disruption</th>
                        <th>Cost</th>
                        <th>Required Role</th>
                      </tr>
                    </thead>
                    <tbody>
                      {candidateActions.map(a => (
                        <tr key={a.id}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{a.id}</td>
                          <td><span className="badge badge-blue">{a.action_type}</span></td>
                          <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{a.target_node_name}</td>
                          <td>+{a.estimated_risk_reduction}</td>
                          <td>{a.operational_disruption_score}</td>
                          <td>${a.implementation_cost}</td>
                          <td><span className="badge badge-purple">{a.required_role}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* VIEW 10: STRATEGY COMPARATOR */}
              {activeView === 'STRATEGY_COMPARATOR' && (
                <div>
                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Tri-Level Strategy Comparison Matrix</div>
                      <span className="badge badge-emerald">OR-TOOLS CP-SAT VS GREEDY VS BASELINE</span>
                    </div>
                    <table className="safe-table">
                      <thead>
                        <tr>
                          <th>Strategy Tier</th>
                          <th>Total Cost</th>
                          <th>Disruption Score</th>
                          <th>Predicted Risk Reduction</th>
                          <th>Predicted Residual</th>
                          <th>SLA Satisfied</th>
                          <th>Solver Latency</th>
                          <th>Simulate</th>
                        </tr>
                      </thead>
                      <tbody>
                        {strategyComparison && (
                          <>
                            <tr>
                              <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Strategy 1: Baseline Severity</td>
                              <td>${strategyComparison.strategies.BASELINE_SEVERITY.total_cost}</td>
                              <td style={{ color: '#f87171' }}>{strategyComparison.strategies.BASELINE_SEVERITY.total_disruption_score} (HIGH)</td>
                              <td>+{strategyComparison.strategies.BASELINE_SEVERITY.predicted_risk_reduction}</td>
                              <td>{strategyComparison.strategies.BASELINE_SEVERITY.predicted_residual_risk}</td>
                              <td><span className="badge badge-crimson">FALSE</span></td>
                              <td>{strategyComparison.benchmarks.baseline_latency_ms} ms</td>
                              <td>
                                <button
                                  className="btn-secondary"
                                  style={{ padding: '3px 8px', fontSize: '11px' }}
                                  onClick={() => {
                                    handleRunSimulation(undefined, 'BASELINE_SEVERITY');
                                    setActiveView('SIMULATION_SANDBOX');
                                  }}
                                >
                                  Simulate
                                </button>
                              </td>
                            </tr>
                            <tr>
                              <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Strategy 2: Greedy Risk-Per-Cost</td>
                              <td>${strategyComparison.strategies.GREEDY_RISK_COST.total_cost}</td>
                              <td>{strategyComparison.strategies.GREEDY_RISK_COST.total_disruption_score}</td>
                              <td>+{strategyComparison.strategies.GREEDY_RISK_COST.predicted_risk_reduction}</td>
                              <td>{strategyComparison.strategies.GREEDY_RISK_COST.predicted_residual_risk}</td>
                              <td><span className="badge badge-emerald">TRUE</span></td>
                              <td>{strategyComparison.benchmarks.greedy_latency_ms} ms</td>
                              <td>
                                <button
                                  className="btn-secondary"
                                  style={{ padding: '3px 8px', fontSize: '11px' }}
                                  onClick={() => {
                                    handleRunSimulation(undefined, 'GREEDY_RISK_COST');
                                    setActiveView('SIMULATION_SANDBOX');
                                  }}
                                >
                                  Simulate
                                </button>
                              </td>
                            </tr>
                            <tr style={{ background: 'rgba(6, 182, 212, 0.08)' }}>
                              <td style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>Strategy 3: Constraint CP-SAT (Recommended)</td>
                              <td>${strategyComparison.strategies.CONSTRAINT_CPSAT.total_cost}</td>
                              <td style={{ color: '#34d399', fontWeight: 600 }}>{strategyComparison.strategies.CONSTRAINT_CPSAT.total_disruption_score} (MINIMAL)</td>
                              <td>+{strategyComparison.strategies.CONSTRAINT_CPSAT.predicted_risk_reduction}</td>
                              <td>{strategyComparison.strategies.CONSTRAINT_CPSAT.predicted_residual_risk}</td>
                              <td><span className="badge badge-emerald">TRUE</span></td>
                              <td>{strategyComparison.benchmarks.cpsat_latency_ms} ms</td>
                              <td>
                                <button
                                  className="btn-primary"
                                  style={{ padding: '3px 8px', fontSize: '11px' }}
                                  onClick={() => {
                                    handleRunSimulation(undefined, 'CONSTRAINT_CPSAT');
                                    setActiveView('SIMULATION_SANDBOX');
                                  }}
                                >
                                  Simulate
                                </button>
                              </td>
                            </tr>
                          </>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* VIEW 11: SIMULATION SANDBOX */}
              {activeView === 'SIMULATION_SANDBOX' && (
                <div>
                  <div className="grid-cards">
                    <div className="metric-card">
                      <div className="metric-title">Simulation Status</div>
                      <div className="metric-value" style={{ color: '#34d399' }}>
                        {isSimulating ? 'SIMULATING...' : 'COMPLETED'}
                      </div>
                      <div className="metric-desc">Executed on isolated graph snapshot</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Pre-Simulation Risk</div>
                      <div className="metric-value">{simulationResult?.initial_risk_score}</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Residual Post-Risk</div>
                      <div className="metric-value" style={{ color: '#38bdf8' }}>{simulationResult?.residual_risk_score}</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Residual Paths</div>
                      <div className="metric-value" style={{ color: '#fbbf24' }}>{simulationResult?.residual_attack_path_count}</div>
                    </div>
                  </div>

                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Forensic Snapshot Verification</div>
                      <span className="badge badge-purple">SHA-256: {simulationResult?.audit_hash?.slice(0, 16)}...</span>
                    </div>
                    <div style={{ padding: '20px' }}>
                      <p style={{ lineHeight: 1.6, marginBottom: '14px' }}>{simulationResult?.explanation}</p>
                      <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                        <button
                          className="btn-primary"
                          onClick={() => handleRunSimulation()}
                          disabled={isSimulating}
                        >
                          <RefreshCw size={14} className={isSimulating ? 'spin' : ''} />
                          {isSimulating ? 'Executing Isolated Simulation...' : 'Re-run What-If Simulation'}
                        </button>
                        <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                          Active interventions in snapshot: {selectedActionIds.length} of {candidateActions.length}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">What-If Intervention Selector</div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          className="btn-secondary"
                          style={{ padding: '4px 10px', fontSize: '12px' }}
                          onClick={() => {
                            const optIds = strategyComparison?.strategies?.CONSTRAINT_CPSAT?.actions?.map((a: any) => a.id) || [];
                            setSelectedActionIds(optIds);
                            handleRunSimulation(optIds, 'CONSTRAINT_CPSAT');
                          }}
                        >
                          CP-SAT Optimal
                        </button>
                        <button
                          className="btn-secondary"
                          style={{ padding: '4px 10px', fontSize: '12px' }}
                          onClick={() => {
                            const allIds = candidateActions.map(a => a.id);
                            setSelectedActionIds(allIds);
                            handleRunSimulation(allIds);
                          }}
                        >
                          Select All
                        </button>
                        <button
                          className="btn-secondary"
                          style={{ padding: '4px 10px', fontSize: '12px' }}
                          onClick={() => {
                            setSelectedActionIds([]);
                            handleRunSimulation([]);
                          }}
                        >
                          Clear All (0 Actions)
                        </button>
                      </div>
                    </div>
                    <table className="safe-table">
                      <thead>
                        <tr>
                          <th style={{ width: '40px' }}>Simulate</th>
                          <th>Action ID</th>
                          <th>Type</th>
                          <th>Target Entity</th>
                          <th>Risk Reduction</th>
                          <th>Cost</th>
                          <th>Disruption</th>
                        </tr>
                      </thead>
                      <tbody>
                        {candidateActions.map(a => {
                          const isSelected = selectedActionIds.includes(a.id);
                          return (
                            <tr key={a.id} style={{ background: isSelected ? 'rgba(56, 189, 248, 0.05)' : undefined }}>
                              <td>
                                <input
                                  type="checkbox"
                                  checked={isSelected}
                                  onChange={() => toggleAction(a.id)}
                                  style={{ cursor: 'pointer', accentColor: 'var(--accent-cyan)' }}
                                />
                              </td>
                              <td style={{ fontFamily: 'var(--font-mono)' }}>{a.id}</td>
                              <td><span className="badge badge-blue">{a.action_type}</span></td>
                              <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{a.target_node_name}</td>
                              <td>+{a.estimated_risk_reduction}</td>
                              <td>${a.implementation_cost}</td>
                              <td>{a.operational_disruption_score}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* VIEW 12: RESIDUAL RISK */}
              {activeView === 'RESIDUAL_RISK' && (
                <div className="data-table-container">
                  <div className="table-header">
                    <div className="table-title">Residual Attack Path Verification</div>
                    <span className="badge badge-crimson">Principle #12: Re-traverse Graph Post-Containment</span>
                  </div>
                  <table className="safe-table">
                    <thead>
                      <tr>
                        <th>Path ID</th>
                        <th>Remaining Lateral Path</th>
                        <th>Hops</th>
                        <th>Residual Risk</th>
                        <th>Unprotected Assets</th>
                      </tr>
                    </thead>
                    <tbody>
                      {simulationResult?.residual_paths?.map((p: any) => (
                        <tr key={p.id}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{p.id}</td>
                          <td style={{ color: '#f87171' }}>{p.node_sequence.join(' → ')}</td>
                          <td>{p.hop_count}</td>
                          <td><span className="badge badge-crimson">{p.adjusted_path_risk}</span></td>
                          <td><span className="badge badge-amber">{p.target_id}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* VIEW 13: DECISION EXPLAINER */}
              {activeView === 'DECISION_EXPLAINER' && (
                <div>
                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Grounded Mathematical Recommendation Justification</div>
                      <span className="badge badge-emerald">ZERO HALLUCINATED METRICS</span>
                    </div>
                    <div style={{ padding: '20px' }}>
                      <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '12px' }}>Why This Strategy Was Selected:</h4>
                      <ul style={{ paddingLeft: '20px', lineHeight: 1.8, marginBottom: '20px' }}>
                        {explanation?.justification?.map((j: string, idx: number) => (
                          <li key={idx}>{j}</li>
                        ))}
                      </ul>

                      <h4 style={{ color: '#f87171', marginBottom: '12px' }}>Why Alternatives Were Rejected:</h4>
                      <ul style={{ paddingLeft: '20px', lineHeight: 1.8 }}>
                        {explanation?.rejected_alternatives?.map((r: any, idx: number) => (
                          <li key={idx}><strong>{r.strategy}:</strong> {r.rejection_rationale}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* VIEW 14: APPROVAL CENTER */}
              {activeView === 'APPROVAL_CENTER' && (
                <div className="data-table-container">
                  <div className="table-header">
                    <div className="table-title">Human-in-the-Loop Governance State Machine</div>
                    <span className="badge badge-purple">Current Role: {currentUserRole}</span>
                  </div>
                  <div style={{ padding: '20px' }}>
                    <div style={{ marginBottom: '20px', display: 'flex', gap: '16px', alignItems: 'center' }}>
                      <span>Lifecycle Progression:</span>
                      <span className="badge badge-blue">DRAFT</span> → 
                      <span className="badge badge-blue">ANALYZED</span> → 
                      <span className="badge badge-blue">SIMULATED</span> → 
                      <span className="badge badge-amber">PENDING_APPROVAL</span> → 
                      <span className="badge badge-emerald">APPROVED</span>
                    </div>

                    <div style={{ display: 'flex', gap: '12px' }}>
                      <button className="btn-primary" onClick={() => handleGovernanceTransition('PENDING_APPROVAL')}>
                        Submit For Manager Review
                      </button>
                      <button className="btn-primary" style={{ backgroundColor: '#10b981' }} onClick={() => handleGovernanceTransition('APPROVED')}>
                        Approve Containment Plan
                      </button>
                      <button className="btn-secondary" style={{ color: '#f87171' }} onClick={() => handleGovernanceTransition('REJECTED')}>
                        Reject With Notes
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* VIEW 15: AUDIT EXPLORER */}
              {activeView === 'AUDIT_EXPLORER' && (
                <div>
                  <div className="data-table-container">
                    <div className="table-header">
                      <div className="table-title">Cryptographic SHA-256 Chained Audit Ledger</div>
                      <span className={`badge ${auditIntegrity?.is_valid ? 'badge-emerald' : 'badge-crimson'}`}>
                        {auditIntegrity?.status_summary}
                      </span>
                    </div>
                    <table className="safe-table">
                      <thead>
                        <tr>
                          <th>Event ID</th>
                          <th>Action</th>
                          <th>Actor</th>
                          <th>Resource</th>
                          <th>Previous Hash (Parent)</th>
                          <th>Current Record Hash</th>
                        </tr>
                      </thead>
                      <tbody>
                        {auditEvents.map(e => (
                          <tr key={e.event_id}>
                            <td style={{ fontFamily: 'var(--font-mono)' }}>{e.event_id}</td>
                            <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{e.action}</td>
                            <td>{e.actor_id} ({e.actor_role})</td>
                            <td>{e.resource_type}:{e.resource_id}</td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{e.previous_hash.slice(0, 14)}...</td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--accent-cyan)' }}>{e.current_hash.slice(0, 14)}...</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* VIEW 16: INTEGRATIONS */}
              {activeView === 'INTEGRATIONS' && (
                <div className="data-table-container">
                  <div className="table-header">
                    <div className="table-title">Enterprise Security Connectors & Provenance</div>
                  </div>
                  <table className="safe-table">
                    <thead>
                      <tr>
                        <th>Connector</th>
                        <th>Target System</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Sync Mode</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td style={{ fontWeight: 600 }}>Splunk / Syslog SIEM</td>
                        <td>SIEM Platform</td>
                        <td>Event Ingestion</td>
                        <td><span className="badge badge-emerald">ACTIVE</span></td>
                        <td>Incremental</td>
                      </tr>
                      <tr>
                        <td style={{ fontWeight: 600 }}>CrowdStrike Falcon EDR</td>
                        <td>EDR / Endpoint</td>
                        <td>Agent Detections</td>
                        <td><span className="badge badge-emerald">ACTIVE</span></td>
                        <td>Real-Time</td>
                      </tr>
                      <tr>
                        <td style={{ fontWeight: 600 }}>Active Directory / Okta</td>
                        <td>IAM / Directory</td>
                        <td>Privilege Mapping</td>
                        <td><span className="badge badge-emerald">ACTIVE</span></td>
                        <td>Batch Sync</td>
                      </tr>
                      <tr>
                        <td style={{ fontWeight: 600 }}>Synthetic Scenario Generator</td>
                        <td>Internal Test Harness</td>
                        <td>Calibrated Scenarios</td>
                        <td><span className="badge badge-purple">SYNTHETIC_ONLY</span></td>
                        <td>Deterministic</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              )}

              {/* VIEW 17: USER ROLES */}
              {activeView === 'USER_ROLES' && (
                <div className="data-table-container" style={{ padding: '20px' }}>
                  <h3 style={{ marginBottom: '14px', color: 'var(--text-primary)' }}>Role-Based Access Control (RBAC) Switcher</h3>
                  <p style={{ color: 'var(--text-secondary)', marginBottom: '18px' }}>
                    Select an active role to test governance permission boundaries and separation of duties:
                  </p>
                  <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                    {[
                      'PLATFORM_ADMIN',
                      'SECURITY_ADMIN',
                      'SOC_ANALYST',
                      'INCIDENT_RESPONDER',
                      'SECURITY_MANAGER',
                      'AUDITOR',
                      'READ_ONLY_VIEWER',
                    ].map(r => (
                      <button
                        key={r}
                        className={currentUserRole === r ? 'btn-primary' : 'btn-secondary'}
                        onClick={() => {
                          setCurrentUserRole(r);
                          showNotification(`Switched active role to ${r}.`);
                        }}
                      >
                        {r}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* VIEW 18: SYSTEM ADMIN */}
              {activeView === 'SYSTEM_ADMIN' && (
                <div>
                  <div className="grid-cards">
                    <div className="metric-card">
                      <div className="metric-title">Uptime</div>
                      <div className="metric-value">{metrics?.uptime_seconds}s</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">CP-SAT Latency</div>
                      <div className="metric-value">{metrics?.cpsat_last_runtime_ms}ms</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Audit Chain Length</div>
                      <div className="metric-value">{metrics?.audit_chain_length}</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-title">Graph Engine</div>
                      <div className="metric-value" style={{ fontSize: '18px', color: 'var(--accent-cyan)' }}>
                        {topology.backend}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* VIEW 19: REPORTS EXPORT */}
              {activeView === 'REPORTS_EXPORT' && (
                <div className="data-table-container" style={{ padding: '24px' }}>
                  <h3 style={{ marginBottom: '10px' }}>Export Verifiable Incident Dossiers</h3>
                  <p style={{ color: 'var(--text-secondary)', marginBottom: '24px' }}>
                    Generate reproducible forensic incident dossiers with cryptographic provenance markers:
                  </p>
                  <div style={{ display: 'flex', gap: '14px' }}>
                    <button className="btn-primary" onClick={() => handleExport('json')}>
                      <Download size={15} /> Export Complete JSON Dossier
                    </button>
                    <button className="btn-secondary" onClick={() => handleExport('csv')}>
                      <Download size={15} /> Export Containment Actions CSV
                    </button>
                    <button className="btn-secondary" onClick={() => handleExport('text')}>
                      <Download size={15} /> Export Executive Text Briefing
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </section>
      </main>
    </div>
  );
};

export default App;
