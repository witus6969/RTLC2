import { useState, useEffect, useMemo } from 'react';
import { useAgentStore } from '../../store/agentStore';
import { useListenerStore } from '../../store/listenerStore';
import { useEventStore } from '../../store/eventStore';
import { useUIStore } from '../../store/uiStore';
import { useCredentialStore } from '../../store/credentialStore';
import { api } from '../../api/client';
import type { ServerInfo } from '../../types';

// SVG Pie Chart component
function PieChart({ data }: { data: { label: string; value: number; color: string }[] }) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  if (total === 0) return <div style={{ color: '#444', textAlign: 'center', padding: 20 }}>No data</div>;

  let cumulative = 0;
  const slices = data.filter(d => d.value > 0).map((d) => {
    const start = cumulative;
    cumulative += d.value / total;
    const startAngle = start * 2 * Math.PI - Math.PI / 2;
    const endAngle = cumulative * 2 * Math.PI - Math.PI / 2;
    const largeArc = d.value / total > 0.5 ? 1 : 0;
    const x1 = 50 + 40 * Math.cos(startAngle);
    const y1 = 50 + 40 * Math.sin(startAngle);
    const x2 = 50 + 40 * Math.cos(endAngle);
    const y2 = 50 + 40 * Math.sin(endAngle);
    return { ...d, path: `M50,50 L${x1},${y1} A40,40 0 ${largeArc},1 ${x2},${y2} Z` };
  });

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
      <svg viewBox="0 0 100 100" width="100" height="100">
        {slices.map((s, i) => (
          <path key={i} d={s.path} fill={s.color} stroke="#0a0a0a" strokeWidth="1" />
        ))}
      </svg>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {data.filter(d => d.value > 0).map((d) => (
          <div key={d.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: d.color, flexShrink: 0 }} />
            <span style={{ color: '#999' }}>{d.label}</span>
            <span style={{ color: '#e0e0e0', fontWeight: 600 }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// SVG Sparkline
function Sparkline({ values, color = '#cc0000' }: { values: number[]; color?: string }) {
  if (values.length === 0) return null;
  const max = Math.max(...values, 1);
  const w = 200, h = 40;
  const points = values.map((v, i) =>
    `${(i / (values.length - 1)) * w},${h - (v / max) * (h - 4)}`
  ).join(' ');

  return (
    <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} style={{ display: 'block' }}>
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
      <polyline points={`0,${h} ${points} ${w},${h}`} fill={`${color}22`} stroke="none" />
    </svg>
  );
}

export default function Dashboard() {
  const agents = useAgentStore((s) => s.agents);
  const listeners = useListenerStore((s) => s.listeners);
  const events = useEventStore((s) => s.events);
  const credentials = useCredentialStore((s) => s.credentials);
  const { setActiveBottomTab, setShowPayloadGenerator, setShowCradleDialog } = useUIStore();
  const fetchAgents = useAgentStore((s) => s.fetch);
  const fetchListeners = useListenerStore((s) => s.fetch);
  const fetchEvents = useEventStore((s) => s.fetch);
  const fetchCreds = useCredentialStore((s) => s.fetch);
  const [serverInfo, setServerInfo] = useState<ServerInfo | null>(null);

  useEffect(() => {
    api.getServerInfo().then(setServerInfo).catch(() => {});
    fetchCreds();
  }, []);

  const aliveCount = agents.filter((a) => a.alive).length;
  const deadCount = agents.length - aliveCount;

  // OS distribution
  const osData = useMemo(() => {
    const counts: Record<string, number> = {};
    agents.forEach((a) => {
      const os = a.os?.toLowerCase().includes('windows') ? 'Windows'
        : a.os?.toLowerCase().includes('linux') ? 'Linux'
        : a.os?.toLowerCase().includes('darwin') || a.os?.toLowerCase().includes('macos') ? 'macOS'
        : 'Other';
      counts[os] = (counts[os] || 0) + 1;
    });
    return [
      { label: 'Windows', value: counts['Windows'] || 0, color: '#0078d4' },
      { label: 'Linux', value: counts['Linux'] || 0, color: '#dd4814' },
      { label: 'macOS', value: counts['macOS'] || 0, color: '#888' },
      { label: 'Other', value: counts['Other'] || 0, color: '#444' },
    ];
  }, [agents]);

  // Activity sparkline (simulate from events)
  const sparkData = useMemo(() => {
    const bins = new Array(24).fill(0);
    const now = Date.now();
    events.forEach((e) => {
      const t = new Date(e.timestamp).getTime();
      const hoursAgo = Math.floor((now - t) / 3600000);
      if (hoursAgo >= 0 && hoursAgo < 24) bins[23 - hoursAgo]++;
    });
    return bins;
  }, [events]);

  // Top active agents
  const topAgents = useMemo(() =>
    [...agents].filter(a => a.alive).sort((a, b) =>
      new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime()
    ).slice(0, 5),
  [agents]);

  const sortedEvents = useMemo(() =>
    [...events].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')).slice(0, 30),
  [events]);

  const versionDisplay = serverInfo?.version || 'v0.6.0';

  const cardStyle = {
    background: '#111', border: '1px solid #1a1a1a', borderRadius: 8, padding: 16,
  };
  const headerStyle = {
    color: '#cc0000', fontSize: 12, fontWeight: 700 as const, textTransform: 'uppercase' as const,
    letterSpacing: '0.5px', marginBottom: 12,
  };

  return (
    <div style={{ padding: 20, overflowY: 'auto', height: '100%' }}>
      {/* Banner */}
      <pre style={{
        color: '#cc0000', fontFamily: 'var(--font-mono)', fontSize: 11,
        textAlign: 'center', background: '#080808', padding: 12,
        border: '1px solid #1a1a1a', borderRadius: 8, marginBottom: 20, lineHeight: 1.3,
      }}>{`  ____  _____ _     ____ ____
 |  _ \\|_   _| |   / ___|___ \\
 | |_) | | | | |  | |     __) |
 |  _ <  | | | |__| |___ / __/
 |_| \\_\\ |_| |____|\\____|_____|
 Red Team Leaders - C2 Framework ${versionDisplay}`}</pre>

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'TOTAL AGENTS', value: agents.length, color: '#cc0000' },
          { label: 'ALIVE', value: aliveCount, color: aliveCount > 0 ? '#00cc00' : '#555' },
          { label: 'DEAD', value: deadCount, color: deadCount > 0 ? '#cc0000' : '#555' },
          { label: 'LISTENERS', value: listeners.length, color: '#0088cc' },
          { label: 'CREDENTIALS', value: credentials.length, color: '#cc8800' },
        ].map((card) => (
          <div key={card.label} style={{
            ...cardStyle, borderTop: `3px solid ${card.color}`, textAlign: 'center',
          }}>
            <div style={{ color: '#555', fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>{card.label}</div>
            <div style={{ color: card.color, fontSize: 32, fontWeight: 700, marginTop: 4 }}>{card.value}</div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        <div style={cardStyle}>
          <div style={headerStyle}>OS Distribution</div>
          <PieChart data={osData} />
        </div>
        <div style={cardStyle}>
          <div style={headerStyle}>Activity (24h)</div>
          <Sparkline values={sparkData} />
          <div style={{ color: '#555', fontSize: 10, marginTop: 8 }}>
            {events.length} events in last 24 hours
          </div>
        </div>
      </div>

      {/* Details Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        {/* Top Agents */}
        <div style={cardStyle}>
          <div style={headerStyle}>Top Active Agents</div>
          {topAgents.length === 0 ? (
            <div style={{ color: '#444', fontSize: 12 }}>No active agents</div>
          ) : (
            <table style={{ width: '100%', fontSize: 11, borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ color: '#555' }}>
                  <th style={{ textAlign: 'left', padding: '4px 8px' }}>ID</th>
                  <th style={{ textAlign: 'left', padding: '4px 8px' }}>Hostname</th>
                  <th style={{ textAlign: 'left', padding: '4px 8px' }}>User</th>
                  <th style={{ textAlign: 'left', padding: '4px 8px' }}>OS</th>
                </tr>
              </thead>
              <tbody>
                {topAgents.map((a) => (
                  <tr key={a.id} style={{ borderTop: '1px solid #1a1a1a' }}>
                    <td style={{ padding: '4px 8px', color: '#cc0000', fontFamily: 'var(--font-mono)' }}>
                      {a.id.slice(0, 8)}
                    </td>
                    <td style={{ padding: '4px 8px', color: '#e0e0e0' }}>{a.hostname}</td>
                    <td style={{ padding: '4px 8px', color: '#999' }}>{a.username}</td>
                    <td style={{ padding: '4px 8px', color: '#999' }}>{a.os}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Recent Credentials */}
        <div style={cardStyle}>
          <div style={headerStyle}>Recent Credentials</div>
          {credentials.length === 0 ? (
            <div style={{ color: '#444', fontSize: 12 }}>No credentials harvested</div>
          ) : (
            credentials.slice(0, 5).map((c) => (
              <div key={c.id} style={{
                padding: '6px 0', borderBottom: '1px solid #1a1a1a',
                display: 'flex', gap: 8, fontSize: 11,
              }}>
                <span style={{
                  background: '#1a1a1a', color: '#cc8800', padding: '1px 6px',
                  borderRadius: 3, fontSize: 10, fontWeight: 600,
                }}>{c.type}</span>
                <span style={{ color: '#e0e0e0' }}>{c.domain ? c.domain + '\\' : ''}{c.username}</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Quick Actions + Server Info */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        <div style={cardStyle}>
          <div style={headerStyle}>Quick Actions</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {[
              { label: 'New Listener', action: () => setActiveBottomTab('listeners') },
              { label: 'Generate Payload', action: () => setShowPayloadGenerator(true) },
              { label: 'Generate Cradle', action: () => setShowCradleDialog(true) },
              { label: 'Refresh All', action: () => { fetchAgents(); fetchListeners(); fetchEvents(); api.getServerInfo().then(setServerInfo).catch(() => {}); } },
            ].map((btn) => (
              <button key={btn.label} onClick={btn.action} className="btn" style={{
                padding: '10px 12px', fontSize: 12,
              }}>
                {btn.label}
              </button>
            ))}
          </div>
        </div>

        <div style={cardStyle}>
          <div style={headerStyle}>Server Info</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', fontSize: 12 }}>
            <span style={{ color: '#555', fontWeight: 600 }}>Version</span>
            <span style={{ color: '#e0e0e0' }}>{versionDisplay}</span>
            <span style={{ color: '#555', fontWeight: 600 }}>Hostname</span>
            <span style={{ color: '#e0e0e0' }}>{serverInfo?.hostname || '-'}</span>
            <span style={{ color: '#555', fontWeight: 600 }}>Uptime</span>
            <span style={{ color: '#e0e0e0' }}>
              {serverInfo?.uptime || (serverInfo?.uptime_seconds
                ? `${Math.floor(serverInfo.uptime_seconds / 3600)}h ${Math.floor((serverInfo.uptime_seconds % 3600) / 60)}m`
                : '-')}
            </span>
            <span style={{ color: '#555', fontWeight: 600 }}>OS</span>
            <span style={{ color: '#e0e0e0' }}>{serverInfo?.os || '-'}</span>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div style={cardStyle}>
        <div style={headerStyle}>Recent Activity</div>
        <div style={{ maxHeight: 200, overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          {sortedEvents.length === 0 ? (
            <div style={{ color: '#444', padding: 12, textAlign: 'center' }}>No events yet</div>
          ) : sortedEvents.map((event, i) => (
            <div key={event.id || i} style={{
              padding: '4px 8px', borderBottom: '1px solid #111', color: '#e0e0e0',
            }}>
              <span style={{ color: '#333' }}>[{event.timestamp}]</span>{' '}
              <span style={{ color: '#cc0000' }}>{event.action}</span>{' - '}
              <span>{event.details}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
