import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';

interface CytoscapeGraphProps {
  nodes: any[];
  edges: any[];
  highlightPathNodeIds?: string[];
  blockedEdgeIds?: string[];
  residualPathEdgeIds?: string[];
  mlRiskMap?: Record<string, any>;
  onSelectNode?: (nodeData: any) => void;
  height?: string | number;
}

interface HoveredNodeData {
  id: string;
  name: string;
  type: string;
  ip_address: string | null;
  hostname: string | null;
  owner: string | null;
  department: string | null;
  criticality: number | string;
  is_compromised: boolean;
  is_crown_jewel: boolean;
  threshold_crossed: boolean;
  ml_probability: number | null;
  risk_tier: string | null;
  isOnAttackPath: boolean;
  properties: Record<string, any>;
}

export const CytoscapeGraph: React.FC<CytoscapeGraphProps> = ({
  nodes,
  edges,
  highlightPathNodeIds = [],
  blockedEdgeIds = [],
  residualPathEdgeIds = [],
  mlRiskMap = {},
  onSelectNode,
  height = '520px',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  // Hover state for interactive rich tooltip
  const [hoveredNode, setHoveredNode] = useState<HoveredNodeData | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  useEffect(() => {
    if (!containerRef.current || nodes.length === 0) return;

    const elements: cytoscape.ElementDefinition[] = [];

    // Map Nodes with semantic cyber topology shapes, icons, and light-theme readable palettes
    nodes.forEach((n) => {
      const isHighlighted = highlightPathNodeIds.includes(n.id);
      const mlData = (mlRiskMap && mlRiskMap[n.id]) || n.ml_risk;
      const isThresholdCrossed = !!(mlData && mlData.threshold_crossed);

      // Extract real IP and Hostname from node or properties
      const ipAddress =
        n.ip_address ||
        n.properties?.ip_address ||
        n.properties?.ip ||
        n.attributes?.ip_address ||
        n.ip ||
        null;

      const hostname =
        n.hostname ||
        n.properties?.hostname ||
        n.attributes?.hostname ||
        null;

      const owner = n.owner || n.properties?.owner || null;
      const department = n.department || n.properties?.department || null;

      let bgColor = '#334155'; // Slate default
      let borderColor = '#475569';
      let shape: cytoscape.Css.NodeShape = 'ellipse';
      let width = 42;
      let height = 42;
      let prefix = '';

      if (n.is_crown_jewel) {
        bgColor = '#d97706'; // Amber gold
        borderColor = '#f59e0b';
        shape = 'diamond';
        width = 54;
        height = 54;
        prefix = '👑 ';
      } else if (isThresholdCrossed) {
        bgColor = '#dc2626'; // Crimson alert for ML threshold crossed
        borderColor = '#ef4444';
        shape = 'ellipse';
        width = 48;
        height = 48;
        prefix = '🚨 ';
      } else if (n.is_compromised) {
        bgColor = '#dc2626'; // Crimson
        borderColor = '#ef4444';
        shape = 'ellipse';
        width = 46;
        height = 46;
        prefix = '⚠️ ';
      } else if (n.type === 'BusinessWorkflow' || n.type === 'BUSINESS_WORKFLOW') {
        bgColor = '#7c3aed'; // Purple
        borderColor = '#a855f7';
        shape = 'hexagon';
        width = 48;
        height = 48;
        prefix = '💼 ';
      } else if (n.type === 'User' || n.type === 'PrivilegedIdentity' || n.type === 'PRIVILEGED_IDENTITY' || n.type === 'USER') {
        bgColor = '#0284c7'; // Deep sky
        borderColor = '#38bdf8';
        shape = 'round-rectangle';
        width = 46;
        height = 36;
        prefix = '👤 ';
      } else if (n.type === 'Device' || n.type === 'Endpoint' || n.type === 'DEVICE' || n.type === 'ENDPOINT') {
        bgColor = '#334155';
        borderColor = '#64748b';
        shape = 'round-rectangle';
        width = 42;
        height = 38;
        prefix = '💻 ';
      } else if (n.type === 'Permission' || n.type === 'PERMISSION') {
        bgColor = '#6d28d9';
        borderColor = '#8b5cf6';
        shape = 'hexagon';
        width = 42;
        height = 42;
        prefix = '🔑 ';
      } else if (n.type === 'Database' || n.type === 'DATABASE') {
        bgColor = '#b45309';
        borderColor = '#f59e0b';
        shape = 'barrel';
        width = 48;
        height = 48;
        prefix = '🗄️ ';
      } else if (n.type === 'Server' || n.type === 'SERVER') {
        bgColor = '#1e3a8a'; // Navy Blue
        borderColor = '#3b82f6';
        shape = 'barrel';
        width = 44;
        height = 44;
        prefix = '🖥️ ';
      }

      const displayName = n.name || n.id;
      const formattedLabel = `${prefix}${displayName.length > 20 ? displayName.slice(0, 18) + '...' : displayName}`;

      elements.push({
        group: 'nodes',
        data: {
          id: n.id,
          label: formattedLabel,
          full_name: displayName,
          name: displayName,
          type: n.type,
          criticality: n.criticality,
          is_compromised: n.is_compromised,
          is_crown_jewel: n.is_crown_jewel,
          provenance: n.provenance,
          properties: n.properties || {},
          ip_address: ipAddress,
          hostname,
          owner,
          department,
          shape,
          width,
          height,
          bgColor,
          borderColor: isHighlighted ? '#0284c7' : (isThresholdCrossed ? '#ef4444' : borderColor),
          borderWidth: isHighlighted ? 4 : (isThresholdCrossed ? 3.5 : (n.is_crown_jewel || n.is_compromised ? 3 : 2)),
          ml_risk: mlData || null,
          ml_probability: mlData ? mlData.ml_probability : null,
          decision_threshold: mlData ? mlData.decision_threshold : null,
          threshold_crossed: isThresholdCrossed,
          risk_tier: mlData ? mlData.risk_tier : null,
          predicted_class: mlData ? mlData.predicted_class : null,
          isOnAttackPath: isHighlighted,
        },
      });
    });

    // Map Edges
    edges.forEach((e) => {
      const isBlocked = blockedEdgeIds.includes(e.id);
      const isResidual = residualPathEdgeIds.includes(e.id);
      let lineColor = '#94a3b8'; // Crisp slate for light canvas
      let lineStyle = 'solid';
      let width = 2;
      let opacity = 0.9;

      if (isBlocked) {
        lineColor = '#cbd5e1';
        lineStyle = 'dashed';
        opacity = 0.35;
        width = 1.5;
      } else if (isResidual) {
        lineColor = '#ea580c'; // Vivid orange for remaining residual paths
        width = 3.5;
        opacity = 1.0;
      } else if (e.evidence_status === 'SUSPECTED') {
        lineStyle = 'dashed';
        lineColor = '#d97706'; // Amber for suspected
        width = 2.5;
      } else if (e.type === 'EXPOSED_TO' || e.type === 'OBSERVED_IN') {
        lineColor = '#dc2626'; // Red for direct attack exposure
        width = 3.0;
      } else if (e.type === 'SUPPORTS_WORKFLOW') {
        lineColor = '#7c3aed'; // Purple for business continuity
        width = 2;
      } else if (e.type === 'HAS_ACCESS_TO' || e.type === 'CAN_ACCESS') {
        lineColor = '#2563eb'; // Blue for credential access
        width = 2;
      }

      elements.push({
        group: 'edges',
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          type: e.type,
          evidence_status: e.evidence_status,
          confidence: e.confidence,
          lineColor,
          lineStyle,
          width,
          opacity,
        },
      });
    });

    // Destroy existing instance if any
    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'shape': 'data(shape)' as any,
            'background-color': 'data(bgColor)',
            'border-color': 'data(borderColor)',
            'border-width': 'data(borderWidth)',
            'label': 'data(label)',
            'color': '#10233f', // Deep navy labels for light workspace (Reference 3)
            'font-size': '11.5px',
            'font-weight': 700,
            'font-family': 'Inter, -apple-system, BlinkMacSystemFont, sans-serif',
            'text-valign': 'bottom',
            'text-margin-y': 7,
            'text-outline-color': '#ffffff', // Clean white outline for readability
            'text-outline-width': 2.5,
            'width': 'data(width)' as any,
            'height': 'data(height)' as any,
            'transition-property': 'background-color, border-color, width, height',
            'transition-duration': 0.2,
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 'data(width)' as any,
            'line-color': 'data(lineColor)',
            'line-style': 'data(lineStyle)' as any,
            'target-arrow-color': 'data(lineColor)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 'data(opacity)' as any,
            'arrow-scale': 0.9,
          },
        },
        {
          selector: ':selected',
          style: {
            'border-color': '#0284c7',
            'border-width': 4.5,
            'line-color': '#0284c7',
            'target-arrow-color': '#0284c7',
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        spacingFactor: 1.4,
      },
    });

    // Node click selection handler
    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data();
      if (onSelectNode) {
        onSelectNode(nodeData);
      }
    });

    // Node hover event listeners for rich real-time tooltip with IP
    cy.on('mouseover', 'node', (evt) => {
      const node = evt.target;
      const data = node.data();
      const pos = node.renderedPosition();

      setHoveredNode({
        id: data.id,
        name: data.full_name || data.label || data.id,
        type: data.type || 'Asset',
        ip_address: data.ip_address || null,
        hostname: data.hostname || null,
        owner: data.owner || null,
        department: data.department || null,
        criticality: data.criticality !== undefined ? data.criticality : '0.50',
        is_compromised: !!data.is_compromised,
        is_crown_jewel: !!data.is_crown_jewel,
        threshold_crossed: !!data.threshold_crossed,
        ml_probability: data.ml_probability !== null ? data.ml_probability : null,
        risk_tier: data.risk_tier || null,
        isOnAttackPath: !!data.isOnAttackPath,
        properties: data.properties || {},
      });

      setTooltipPos({ x: pos.x, y: pos.y });
    });

    cy.on('mouseout', 'node', () => {
      setHoveredNode(null);
      setTooltipPos(null);
    });

    cy.on('pan zoom', () => {
      // Clear tooltip on camera pan/zoom to prevent misplaced coordinates
      setHoveredNode(null);
      setTooltipPos(null);
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [nodes, edges, highlightPathNodeIds, blockedEdgeIds, residualPathEdgeIds, mlRiskMap]);

  // Graph canvas controls
  const handleZoomIn = () => {
    if (cyRef.current) {
      cyRef.current.zoom({
        level: cyRef.current.zoom() * 1.3,
        renderedPosition: { x: cyRef.current.width() / 2, y: cyRef.current.height() / 2 },
      });
    }
  };

  const handleZoomOut = () => {
    if (cyRef.current) {
      cyRef.current.zoom({
        level: cyRef.current.zoom() * 0.77,
        renderedPosition: { x: cyRef.current.width() / 2, y: cyRef.current.height() / 2 },
      });
    }
  };

  const handleFit = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 30);
    }
  };

  const handleReset = () => {
    if (cyRef.current) {
      cyRef.current.reset();
      cyRef.current.fit(undefined, 30);
    }
  };

  // Compute tooltip position clamped within container
  const getTooltipStyle = () => {
    if (!tooltipPos || !containerRef.current) return { display: 'none' };
    const rect = containerRef.current.getBoundingClientRect();
    const width = 310;
    
    // Position to the right-top of the node, flipping to left if near right edge
    let left = tooltipPos.x + 18;
    if (left + width > rect.width - 20) {
      left = Math.max(10, tooltipPos.x - width - 18);
    }

    let top = Math.max(12, tooltipPos.y - 45);
    if (top + 260 > rect.height) {
      top = Math.max(12, rect.height - 275);
    }

    return {
      left: `${left}px`,
      top: `${top}px`,
    };
  };

  return (
    <div
      ref={containerRef}
      className="cytoscape-canvas"
      style={{ height, position: 'relative' }}
    >
      {/* Floating Graph Controls (Reference 3) */}
      <div className="graph-controls-overlay">
        <button
          type="button"
          className="graph-control-btn"
          title="Zoom In"
          onClick={handleZoomIn}
        >
          +
        </button>
        <button
          type="button"
          className="graph-control-btn"
          title="Zoom Out"
          onClick={handleZoomOut}
        >
          −
        </button>
        <button
          type="button"
          className="graph-control-btn"
          title="Fit to Screen"
          onClick={handleFit}
        >
          ⛶
        </button>
        <button
          type="button"
          className="graph-control-btn"
          title="Reset View"
          onClick={handleReset}
        >
          ↺
        </button>
      </div>

      {/* MANDATORY HOVER TOOLTIP — Prominent IP Address Display (Reference 3) */}
      {hoveredNode && tooltipPos && (
        <div
          className="graph-tooltip-card"
          style={getTooltipStyle()}
          onMouseEnter={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '15px' }}>
                {hoveredNode.is_crown_jewel ? '👑' : hoveredNode.threshold_crossed || hoveredNode.is_compromised ? '🚨' : '🛡️'}
              </span>
              <strong style={{ fontSize: '13px', color: '#10233f', maxWidth: '170px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {hoveredNode.name}
              </strong>
            </div>
            <span className="badge badge-purple" style={{ fontSize: '10px' }}>
              {hoveredNode.type}
            </span>
          </div>

          {/* CRITICAL REQUIREMENT: Prominent Monospace IP Address Box */}
          <div
            style={{
              background: '#edf3f9',
              border: '1px solid #cde7ff',
              borderRadius: '6px',
              padding: '8px 10px',
              marginBottom: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '8px',
            }}
          >
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '9px', fontWeight: 800, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.6px' }}>
                IP ADDRESS
              </span>
              {hoveredNode.ip_address ? (
                <span
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '13.5px',
                    fontWeight: 700,
                    color: '#10233f',
                    letterSpacing: '0.2px',
                  }}
                >
                  {hoveredNode.ip_address}
                </span>
              ) : (
                <span style={{ fontStyle: 'italic', fontSize: '11px', color: '#94a3b8' }}>
                  IP address unavailable
                </span>
              )}
            </div>
            {hoveredNode.ip_address && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  if (hoveredNode.ip_address) {
                    navigator.clipboard.writeText(hoveredNode.ip_address);
                    setCopiedIp(hoveredNode.ip_address);
                    setTimeout(() => setCopiedIp(null), 2000);
                  }
                }}
                style={{
                  background: copiedIp === hoveredNode.ip_address ? '#16a34a' : '#0284c7',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '4px',
                  padding: '4px 8px',
                  fontSize: '10.5px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  boxShadow: '0 1px 3px rgba(2, 132, 199, 0.25)',
                  transition: 'background 0.15s ease',
                }}
                title="Copy IP to clipboard"
              >
                {copiedIp === hoveredNode.ip_address ? '✓ Copied' : '📋 Copy'}
              </button>
            )}
          </div>

          {/* Hostname & Metadata */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px', fontSize: '11px', marginBottom: '8px' }}>
            <div>
              <span style={{ color: '#64748b' }}>Hostname: </span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#10233f' }}>
                {hoveredNode.hostname || hoveredNode.id}
              </span>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Criticality: </span>
              <strong style={{ color: '#10233f' }}>
                {typeof hoveredNode.criticality === 'number'
                  ? hoveredNode.criticality.toFixed(2)
                  : hoveredNode.criticality}
              </strong>
            </div>
            {hoveredNode.owner && (
              <div>
                <span style={{ color: '#64748b' }}>Owner: </span>
                <span style={{ fontWeight: 600, color: '#10233f' }}>{hoveredNode.owner}</span>
              </div>
            )}
            {hoveredNode.department && (
              <div>
                <span style={{ color: '#64748b' }}>Dept: </span>
                <span style={{ fontWeight: 600, color: '#10233f' }}>{hoveredNode.department}</span>
              </div>
            )}
          </div>

          {/* Threat / ML Risk Status */}
          <div style={{ borderTop: '1px solid #e2e8f0', paddingTop: '8px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '6px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              {hoveredNode.is_crown_jewel && (
                <span className="badge badge-amber" style={{ fontSize: '9.5px' }}>👑 CROWN JEWEL</span>
              )}
              {hoveredNode.is_compromised && (
                <span className="badge badge-red" style={{ fontSize: '9.5px' }}>⚠️ COMPROMISED</span>
              )}
              {hoveredNode.threshold_crossed && (
                <span className="badge badge-red" style={{ fontSize: '9.5px' }}>🚨 THREAT DETECTED</span>
              )}
              {!hoveredNode.is_crown_jewel && !hoveredNode.is_compromised && !hoveredNode.threshold_crossed && (
                <span className="badge badge-green" style={{ fontSize: '9.5px' }}>🟢 BENIGN / HEALTHY</span>
              )}
            </div>

            {hoveredNode.ml_probability !== null && (
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10.5px', fontWeight: 700, color: hoveredNode.threshold_crossed ? '#dc2626' : '#16a34a' }}>
                P(threat): {(hoveredNode.ml_probability * 100).toFixed(1)}%
              </span>
            )}
          </div>

          {/* Attack Path Indicator */}
          {hoveredNode.isOnAttackPath && (
            <div style={{ marginTop: '6px', padding: '3px 6px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '4px', fontSize: '10px', color: '#dc2626', fontWeight: 700 }}>
              ⚡ High-Risk Asset on Active Attack Route
            </div>
          )}
        </div>
      )}
    </div>
  );
};
