import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

interface CytoscapeGraphProps {
  nodes: any[];
  edges: any[];
  highlightPathNodeIds?: string[];
  onSelectNode?: (nodeData: any) => void;
}

export const CytoscapeGraph: React.FC<CytoscapeGraphProps> = ({
  nodes,
  edges,
  highlightPathNodeIds = [],
  onSelectNode,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    if (!containerRef.current || nodes.length === 0) return;

    const elements: cytoscape.ElementDefinition[] = [];

    // Map Nodes
    nodes.forEach((n) => {
      const isHighlighted = highlightPathNodeIds.includes(n.id);
      let bgColor = '#334155'; // Slate default
      let borderColor = '#475569';

      if (n.is_crown_jewel) {
        bgColor = '#b45309'; // Amber gold
        borderColor = '#f59e0b';
      } else if (n.is_compromised) {
        bgColor = '#991b1b'; // Crimson
        borderColor = '#ef4444';
      } else if (n.type === 'BusinessWorkflow') {
        bgColor = '#581c87'; // Purple
        borderColor = '#a855f7';
      } else if (n.type === 'Server') {
        bgColor = '#1e3a8a'; // Blue
        borderColor = '#3b82f6';
      }

      elements.push({
        group: 'nodes',
        data: {
          id: n.id,
          label: n.name.length > 20 ? n.name.slice(0, 18) + '...' : n.name,
          full_name: n.name,
          type: n.type,
          criticality: n.criticality,
          is_compromised: n.is_compromised,
          is_crown_jewel: n.is_crown_jewel,
          provenance: n.provenance,
          bgColor,
          borderColor,
          borderWidth: isHighlighted ? 4 : 2,
        },
      });
    });

    // Map Edges
    edges.forEach((e) => {
      let lineColor = '#334155';
      let lineStyle = 'solid';

      if (e.evidence_status === 'SUSPECTED') {
        lineStyle = 'dashed';
        lineColor = '#f59e0b';
      } else if (e.type === 'EXPOSED_TO' || e.type === 'OBSERVED_IN') {
        lineColor = '#ef4444';
      } else if (e.type === 'SUPPORTS_WORKFLOW') {
        lineColor = '#a855f7';
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
            'background-color': 'data(bgColor)',
            'border-color': 'data(borderColor)',
            'border-width': 'data(borderWidth)',
            'label': 'data(label)',
            'color': '#f8fafc',
            'font-size': '11px',
            'font-family': 'Inter, sans-serif',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'width': 38,
            'height': 38,
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': 'data(lineColor)',
            'line-style': 'data(lineStyle)' as any,
            'target-arrow-color': 'data(lineColor)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 0.8,
          },
        },
        {
          selector: ':selected',
          style: {
            'border-color': '#38bdf8',
            'border-width': 4,
            'line-color': '#38bdf8',
            'target-arrow-color': '#38bdf8',
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

    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data();
      if (onSelectNode) {
        onSelectNode(nodeData);
      }
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [nodes, edges, highlightPathNodeIds]);

  return <div ref={containerRef} className="cytoscape-canvas" />;
};
