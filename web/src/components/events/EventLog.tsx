import { useMemo } from 'react';
import { useEventStore } from '../../store/eventStore';

const EVENT_TYPES = ['all', 'agent_checkin', 'agent_dead', 'agent_task_complete', 'credential_added', 'listener_started', 'listener_stopped'];

const EVENT_COLORS: Record<string, string> = {
  agent_checkin: '#00cc00',
  agent_dead: '#cc0000',
  agent_task_complete: '#0088cc',
  credential_added: '#cc8800',
  listener_started: '#00cc88',
  listener_stopped: '#cc4400',
};

function getEventColor(action: string): string {
  for (const [key, color] of Object.entries(EVENT_COLORS)) {
    if (action.toLowerCase().includes(key.replace('_', ' ')) || action.toLowerCase().includes(key)) return color;
  }
  return '#888';
}

export default function EventLog() {
  const events = useEventStore((s) => s.events);
  const filterType = useEventStore((s) => s.filterType);
  const searchQuery = useEventStore((s) => s.searchQuery);
  const page = useEventStore((s) => s.page);
  const pageSize = useEventStore((s) => s.pageSize);
  const setFilterType = useEventStore((s) => s.setFilterType);
  const setSearchQuery = useEventStore((s) => s.setSearchQuery);
  const setPage = useEventStore((s) => s.setPage);

  const filtered = useMemo(() => {
    let result = [...events].sort((a, b) =>
      (b.timestamp || '').localeCompare(a.timestamp || '')
    );
    if (filterType !== 'all') {
      result = result.filter(e =>
        e.action?.toLowerCase().includes(filterType.replace('_', ' ')) ||
        e.action?.toLowerCase().includes(filterType)
      );
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(e =>
        (e.action || '').toLowerCase().includes(q) ||
        (e.details || '').toLowerCase().includes(q) ||
        (e.target || '').toLowerCase().includes(q)
      );
    }
    return result;
  }, [events, filterType, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const paged = filtered.slice(page * pageSize, (page + 1) * pageSize);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rtlc2_events_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ height: '100%', overflow: 'hidden', display: 'flex', flexDirection: 'column', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
      {/* Toolbar */}
      <div style={{
        display: 'flex', gap: 12, alignItems: 'center', padding: '8px 12px',
        borderBottom: '1px solid #1a1a1a', background: '#0d0d0d', flexShrink: 0, flexWrap: 'wrap',
      }}>
        <span style={{ color: '#888', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' }}>
          Event Log ({filtered.length})
        </span>
        <input
          type="text"
          placeholder="Search events..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{
            padding: '4px 8px', background: '#0a0a0a', border: '1px solid #333',
            borderRadius: 3, color: '#e0e0e0', fontSize: 11, fontFamily: 'inherit',
            outline: 'none', width: 180,
          }}
        />
        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          style={{
            padding: '4px 8px', background: '#0a0a0a', border: '1px solid #333',
            borderRadius: 3, color: '#e0e0e0', fontSize: 11, fontFamily: 'inherit', outline: 'none',
          }}
        >
          {EVENT_TYPES.map(t => (
            <option key={t} value={t}>{t === 'all' ? 'All Events' : t.replace(/_/g, ' ')}</option>
          ))}
        </select>
        <button className="btn btn--small" onClick={handleExport} style={{ fontSize: 10 }}>Export JSON</button>
        <div style={{ flex: 1 }} />
        <div style={{ display: 'flex', gap: 4, alignItems: 'center', fontSize: 10, color: '#555' }}>
          <button className="btn btn--small" disabled={page === 0} onClick={() => setPage(page - 1)} style={{ fontSize: 10 }}>Prev</button>
          <span>{page + 1} / {totalPages}</span>
          <button className="btn btn--small" disabled={page >= totalPages - 1} onClick={() => setPage(page + 1)} style={{ fontSize: 10 }}>Next</button>
        </div>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
          <thead>
            <tr style={{ color: '#555', borderBottom: '1px solid #1a1a1a', position: 'sticky', top: 0, background: '#0a0a0a' }}>
              <th style={{ textAlign: 'left', padding: '6px 8px', width: 160 }}>Time</th>
              <th style={{ textAlign: 'left', padding: '6px 8px', width: 160 }}>Type</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Details</th>
            </tr>
          </thead>
          <tbody>
            {paged.length === 0 ? (
              <tr><td colSpan={3} style={{ textAlign: 'center', color: '#444', padding: 20 }}>No events</td></tr>
            ) : paged.map((event, i) => (
              <tr key={event.id || i} style={{ borderBottom: '1px solid #111' }}>
                <td style={{ padding: '4px 8px', color: '#555', whiteSpace: 'nowrap' }}>{event.timestamp}</td>
                <td style={{ padding: '4px 8px' }}>
                  <span style={{
                    display: 'inline-block',
                    padding: '1px 6px',
                    borderRadius: 3,
                    fontSize: 10,
                    fontWeight: 600,
                    background: getEventColor(event.action) + '22',
                    color: getEventColor(event.action),
                    border: `1px solid ${getEventColor(event.action)}44`,
                  }}>
                    {event.action}
                  </span>
                </td>
                <td style={{ padding: '4px 8px', color: '#a0a0a0' }}>
                  {event.target && <span style={{ color: '#888' }}>{event.target} - </span>}
                  {event.details}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
