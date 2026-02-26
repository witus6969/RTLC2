// ═══════════════════════════════════════════════════════════════
//  RTLC2 Agent Network Topology Graph
//  SVG-based force-directed layout showing teamserver, listeners,
//  and agents with their interconnections.
// ═══════════════════════════════════════════════════════════════

import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { useAgentStore } from '../../store/agentStore';
import { useListenerStore } from '../../store/listenerStore';
import { useUIStore } from '../../store/uiStore';
import type { Agent, Listener } from '../../types';
import { ListenerProtocol } from '../../types';

// ── Types ────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  label: string;
  sublabel: string;
  type: 'teamserver' | 'listener' | 'agent';
  color: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  data?: Agent | Listener;
}

interface GraphEdge {
  source: string;
  target: string;
  type: 'listener' | 'agent' | 'smb_pivot';
  label?: string;
}

interface TooltipState {
  x: number;
  y: number;
  node: GraphNode;
}

// ── Constants ────────────────────────────────────────────────

const NODE_COLORS = {
  teamserver: '#cc0000',
  listener_active: '#00cc00',
  listener_stopped: '#808080',
  agent_alive: '#00cc00',
  agent_dead: '#cc0000',
  agent_away: '#cccc00',
};

const EDGE_COLORS = {
  listener: '#444444',
  agent: '#333333',
  smb_pivot: '#ff6600',
};

const SIMULATION_STEPS = 200;
const REPULSION = 4000;
const ATTRACTION = 0.004;
const DAMPING = 0.9;
const CENTER_PULL = 0.01;

// ── Force Simulation ─────────────────────────────────────────

function runForceSimulation(nodes: GraphNode[], edges: GraphEdge[], width: number, height: number) {
  const nodeMap = new Map<string, GraphNode>();
  nodes.forEach((n) => nodeMap.set(n.id, n));

  for (let step = 0; step < SIMULATION_STEPS; step++) {
    // Repulsion between all pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = REPULSION / (dist * dist);
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        a.vx += dx;
        a.vy += dy;
        b.vx -= dx;
        b.vy -= dy;
      }
    }

    // Attraction along edges
    for (const edge of edges) {
      const src = nodeMap.get(edge.source);
      const tgt = nodeMap.get(edge.target);
      if (!src || !tgt) continue;
      const dx = tgt.x - src.x;
      const dy = tgt.y - src.y;
      const force = ATTRACTION * Math.sqrt(dx * dx + dy * dy);
      src.vx += dx * force;
      src.vy += dy * force;
      tgt.vx -= dx * force;
      tgt.vy -= dy * force;
    }

    // Center pull
    const cx = width / 2;
    const cy = height / 2;
    for (const node of nodes) {
      node.vx += (cx - node.x) * CENTER_PULL;
      node.vy += (cy - node.y) * CENTER_PULL;
    }

    // Teamserver stays centered vertically
    const ts = nodes.find((n) => n.type === 'teamserver');
    if (ts) {
      ts.vx *= 0.1;
      ts.vy *= 0.1;
      ts.x = cx;
      ts.y = cy;
    }

    // Apply velocity with damping
    for (const node of nodes) {
      node.vx *= DAMPING;
      node.vy *= DAMPING;
      node.x += node.vx;
      node.y += node.vy;
      // Clamp to bounds
      const pad = node.radius + 20;
      node.x = Math.max(pad, Math.min(width - pad, node.x));
      node.y = Math.max(pad, Math.min(height - pad, node.y));
    }
  }

  return nodes;
}

// ── Helper ───────────────────────────────────────────────────

function getAgentNodeColor(agent: Agent): string {
  if (!agent.alive) return NODE_COLORS.agent_dead;
  // "away" = last_seen > 3x sleep_interval ago
  const lastSeen = new Date(agent.last_seen).getTime();
  const threshold = (agent.sleep_interval || 10) * 3 * 1000;
  if (Date.now() - lastSeen > threshold) return NODE_COLORS.agent_away;
  return NODE_COLORS.agent_alive;
}

function protocolLabel(protocol: number): string {
  const labels: Record<number, string> = {
    [ListenerProtocol.HTTP]: 'HTTP',
    [ListenerProtocol.HTTPS]: 'HTTPS',
    [ListenerProtocol.TCP]: 'TCP',
    [ListenerProtocol.SMB]: 'SMB',
    [ListenerProtocol.DNS]: 'DNS',
  };
  return labels[protocol] || 'UNKNOWN';
}

// ── Component ────────────────────────────────────────────────

export default function AgentGraph() {
  const agents = useAgentStore((s) => s.agents);
  const selectAgent = useAgentStore((s) => s.selectAgent);
  const listeners = useListenerStore((s) => s.listeners);
  const { openAgentTab } = useUIStore();

  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const [dragNode, setDragNode] = useState<string | null>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);

  // Resize observer
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const ro = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) {
        setDimensions({
          width: entry.contentRect.width,
          height: entry.contentRect.height,
        });
      }
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  // Build graph data
  const graphData = useMemo(() => {
    const newNodes: GraphNode[] = [];
    const newEdges: GraphEdge[] = [];
    const w = dimensions.width;
    const h = dimensions.height;

    // Teamserver root node
    newNodes.push({
      id: 'teamserver',
      label: 'Teamserver',
      sublabel: 'RTLC2',
      type: 'teamserver',
      color: NODE_COLORS.teamserver,
      x: w / 2,
      y: h / 2,
      vx: 0,
      vy: 0,
      radius: 24,
    });

    // Listener nodes in a ring around teamserver
    listeners.forEach((listener, i) => {
      const angle = (2 * Math.PI * i) / Math.max(listeners.length, 1);
      const dist = 150;
      newNodes.push({
        id: `listener-${listener.id}`,
        label: listener.config.name || listener.id.slice(0, 8),
        sublabel: `${protocolLabel(listener.config.protocol)} :${listener.config.bind_port}`,
        type: 'listener',
        color: listener.active ? NODE_COLORS.listener_active : NODE_COLORS.listener_stopped,
        x: w / 2 + Math.cos(angle) * dist,
        y: h / 2 + Math.sin(angle) * dist,
        vx: 0,
        vy: 0,
        radius: 16,
        data: listener,
      });
      newEdges.push({
        source: 'teamserver',
        target: `listener-${listener.id}`,
        type: 'listener',
      });
    });

    // Agent nodes around their listeners
    agents.forEach((agent, i) => {
      const listenerNodeId = `listener-${agent.listener_id}`;
      const parentNode = newNodes.find((n) => n.id === listenerNodeId);
      const baseX = parentNode ? parentNode.x : w / 2;
      const baseY = parentNode ? parentNode.y : h / 2;
      const scatter = 120 + Math.random() * 60;
      const angle = (2 * Math.PI * i) / Math.max(agents.length, 1) + Math.random() * 0.3;

      newNodes.push({
        id: `agent-${agent.id}`,
        label: agent.hostname,
        sublabel: `${agent.username} | ${agent.internal_ip}`,
        type: 'agent',
        color: getAgentNodeColor(agent),
        x: baseX + Math.cos(angle) * scatter,
        y: baseY + Math.sin(angle) * scatter,
        vx: 0,
        vy: 0,
        radius: 12,
        data: agent,
      });

      // Edge from listener to agent
      const targetId = parentNode ? listenerNodeId : 'teamserver';
      newEdges.push({
        source: targetId,
        target: `agent-${agent.id}`,
        type: 'agent',
      });
    });

    // Detect SMB pivot connections (agents whose listener is SMB type)
    agents.forEach((agent) => {
      const listener = listeners.find((l) => l.id === agent.listener_id);
      if (listener && listener.config.protocol === ListenerProtocol.SMB) {
        // Find the parent agent that might be pivoting through this SMB pipe
        // Heuristic: look for agents on the same internal subnet
        agents.forEach((other) => {
          if (other.id === agent.id) return;
          if (other.internal_ip && agent.internal_ip) {
            const agentSubnet = agent.internal_ip.split('.').slice(0, 3).join('.');
            const otherSubnet = other.internal_ip.split('.').slice(0, 3).join('.');
            if (agentSubnet === otherSubnet && other.alive && agent.alive) {
              // Check if we haven't already added this edge
              const edgeId = [agent.id, other.id].sort().join('-');
              if (!newEdges.some((e) => {
                const eid = [e.source.replace('agent-', ''), e.target.replace('agent-', '')].sort().join('-');
                return eid === edgeId && e.type === 'smb_pivot';
              })) {
                newEdges.push({
                  source: `agent-${other.id}`,
                  target: `agent-${agent.id}`,
                  type: 'smb_pivot',
                  label: 'SMB Pipe',
                });
              }
            }
          }
        });
      }
    });

    // Run force simulation
    const simulated = runForceSimulation(newNodes, newEdges, w, h);
    return { nodes: simulated, edges: newEdges };
  }, [agents, listeners, dimensions]);

  // Update state when graph data changes
  useEffect(() => {
    setNodes([...graphData.nodes]);
    setEdges([...graphData.edges]);
  }, [graphData]);

  // ── Drag Handling ──────────────────────────────────────────

  const handleMouseDown = useCallback((nodeId: string) => {
    setDragNode(nodeId);
  }, []);

  useEffect(() => {
    if (!dragNode) return;

    const handleMouseMove = (e: MouseEvent) => {
      const svg = svgRef.current;
      if (!svg) return;
      const rect = svg.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      setNodes((prev) =>
        prev.map((n) => (n.id === dragNode ? { ...n, x, y } : n))
      );
    };

    const handleMouseUp = () => {
      setDragNode(null);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [dragNode]);

  // ── Click / Hover ──────────────────────────────────────────

  const handleNodeClick = useCallback((node: GraphNode) => {
    if (node.type === 'agent' && node.data) {
      const agent = node.data as Agent;
      selectAgent(agent.id);
    }
  }, [selectAgent]);

  const handleNodeDoubleClick = useCallback((node: GraphNode) => {
    if (node.type === 'agent' && node.data) {
      const agent = node.data as Agent;
      openAgentTab(agent.id, agent.hostname);
    }
  }, [openAgentTab]);

  const handleNodeHover = useCallback((e: React.MouseEvent, node: GraphNode | null) => {
    if (node) {
      setTooltip({ x: e.clientX, y: e.clientY, node });
    } else {
      setTooltip(null);
    }
  }, []);

  // ── Render ─────────────────────────────────────────────────

  const nodeMap = useMemo(() => {
    const map = new Map<string, GraphNode>();
    nodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [nodes]);

  return (
    <div ref={containerRef} style={{ width: '100%', height: '100%', position: 'relative', background: 'var(--bg-primary)' }}>
      <svg
        ref={svgRef}
        width={dimensions.width}
        height={dimensions.height}
        style={{ display: 'block' }}
      >
        <defs>
          {/* Glow filter for alive agents */}
          <filter id="glow-green" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Arrow marker for SMB edges */}
          <marker id="arrow-smb" viewBox="0 0 10 6" refX="10" refY="3" markerWidth="10" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 3 L 0 6 z" fill={EDGE_COLORS.smb_pivot} />
          </marker>
        </defs>

        {/* Edges */}
        {edges.map((edge, i) => {
          const src = nodeMap.get(edge.source);
          const tgt = nodeMap.get(edge.target);
          if (!src || !tgt) return null;

          const isSmb = edge.type === 'smb_pivot';
          return (
            <g key={`edge-${i}`}>
              <line
                x1={src.x}
                y1={src.y}
                x2={tgt.x}
                y2={tgt.y}
                stroke={EDGE_COLORS[edge.type]}
                strokeWidth={isSmb ? 2 : 1}
                strokeDasharray={isSmb ? '6,3' : undefined}
                markerEnd={isSmb ? 'url(#arrow-smb)' : undefined}
                opacity={0.6}
              />
              {edge.label && (
                <text
                  x={(src.x + tgt.x) / 2}
                  y={(src.y + tgt.y) / 2 - 6}
                  fill={EDGE_COLORS.smb_pivot}
                  fontSize="9"
                  fontFamily="var(--font-mono)"
                  textAnchor="middle"
                  opacity={0.8}
                >
                  {edge.label}
                </text>
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map((node) => {
          const isTeamserver = node.type === 'teamserver';
          const glowFilter = node.color === NODE_COLORS.agent_alive
            ? 'url(#glow-green)'
            : node.color === NODE_COLORS.teamserver
              ? 'url(#glow-red)'
              : undefined;

          return (
            <g
              key={node.id}
              style={{ cursor: dragNode === node.id ? 'grabbing' : 'pointer' }}
              onMouseDown={() => handleMouseDown(node.id)}
              onClick={() => handleNodeClick(node)}
              onDoubleClick={() => handleNodeDoubleClick(node)}
              onMouseEnter={(e) => handleNodeHover(e, node)}
              onMouseLeave={(e) => handleNodeHover(e, null)}
            >
              {/* Node shape */}
              {isTeamserver ? (
                <rect
                  x={node.x - node.radius}
                  y={node.y - node.radius}
                  width={node.radius * 2}
                  height={node.radius * 2}
                  rx="4"
                  fill="var(--bg-elevated)"
                  stroke={node.color}
                  strokeWidth="2"
                  filter={glowFilter}
                />
              ) : (
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={node.radius}
                  fill="var(--bg-elevated)"
                  stroke={node.color}
                  strokeWidth="2"
                  filter={glowFilter}
                />
              )}

              {/* Node icon */}
              {isTeamserver && (
                <text
                  x={node.x}
                  y={node.y + 1}
                  fill={node.color}
                  fontSize="16"
                  fontWeight="bold"
                  textAnchor="middle"
                  dominantBaseline="central"
                  style={{ pointerEvents: 'none' }}
                >
                  R
                </text>
              )}
              {node.type === 'listener' && (
                <text
                  x={node.x}
                  y={node.y + 1}
                  fill={node.color}
                  fontSize="11"
                  fontWeight="bold"
                  textAnchor="middle"
                  dominantBaseline="central"
                  style={{ pointerEvents: 'none' }}
                >
                  L
                </text>
              )}
              {node.type === 'agent' && (
                <text
                  x={node.x}
                  y={node.y + 1}
                  fill={node.color}
                  fontSize="10"
                  fontWeight="bold"
                  textAnchor="middle"
                  dominantBaseline="central"
                  style={{ pointerEvents: 'none' }}
                >
                  A
                </text>
              )}

              {/* Label below node */}
              <text
                x={node.x}
                y={node.y + node.radius + 14}
                fill="var(--text-secondary)"
                fontSize="10"
                fontFamily="var(--font-sans)"
                textAnchor="middle"
                style={{ pointerEvents: 'none' }}
              >
                {node.label}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Tooltip */}
      {tooltip && (
        <div
          style={{
            position: 'fixed',
            left: tooltip.x + 12,
            top: tooltip.y - 10,
            background: 'var(--bg-elevated)',
            border: '1px solid var(--border-secondary)',
            borderRadius: 'var(--radius-md)',
            padding: '8px 12px',
            zIndex: 2000,
            pointerEvents: 'none',
            boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
            maxWidth: '280px',
          }}
        >
          <div style={{ fontWeight: 700, color: tooltip.node.color, fontSize: '12px', marginBottom: '4px' }}>
            {tooltip.node.label}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
            {tooltip.node.sublabel}
          </div>
          {tooltip.node.type === 'agent' && tooltip.node.data && (
            <div style={{ marginTop: '6px', fontSize: '11px', color: 'var(--text-dim)' }}>
              {(() => {
                const a = tooltip.node.data as Agent;
                return (
                  <>
                    <div>PID: {a.pid} ({a.process_name})</div>
                    <div>OS: {a.os} / {a.arch}</div>
                    <div>Sleep: {a.sleep_interval}s ({a.jitter}% jitter)</div>
                    <div style={{ color: a.alive ? 'var(--green)' : 'var(--red-primary)' }}>
                      {a.alive ? 'ALIVE' : 'DEAD'}
                    </div>
                  </>
                );
              })()}
            </div>
          )}
          {tooltip.node.type === 'agent' && (
            <div style={{ marginTop: '4px', fontSize: '10px', color: 'var(--text-dim)' }}>
              Double-click to interact
            </div>
          )}
        </div>
      )}

      {/* Legend */}
      <div style={{
        position: 'absolute',
        bottom: '12px',
        right: '12px',
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border-primary)',
        borderRadius: 'var(--radius-md)',
        padding: '8px 12px',
        fontSize: '10px',
        color: 'var(--text-muted)',
      }}>
        <div style={{ fontWeight: 700, marginBottom: '4px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Legend
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
          <span><span style={{ color: NODE_COLORS.agent_alive }}>--</span> Alive</span>
          <span><span style={{ color: NODE_COLORS.agent_dead }}>--</span> Dead</span>
          <span><span style={{ color: NODE_COLORS.agent_away }}>--</span> Away</span>
          <span><span style={{ color: EDGE_COLORS.smb_pivot }}>- -</span> SMB Pivot</span>
        </div>
      </div>

      {/* Stats */}
      <div style={{
        position: 'absolute',
        top: '12px',
        left: '12px',
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border-primary)',
        borderRadius: 'var(--radius-md)',
        padding: '6px 12px',
        fontSize: '11px',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
      }}>
        {agents.filter((a) => a.alive).length}/{agents.length} agents | {listeners.filter((l) => l.active).length}/{listeners.length} listeners
      </div>
    </div>
  );
}
