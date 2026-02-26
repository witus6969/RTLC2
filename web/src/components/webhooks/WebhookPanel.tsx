// ═══════════════════════════════════════════════════════════════
//  RTLC2 Webhook Management Panel
//  Lists, adds, deletes, toggles, and tests webhooks.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect } from 'react';
import { useWebhookStore } from '../../store/webhookStore';

const WEBHOOK_TYPES = [
  { value: 'slack', label: 'Slack' },
  { value: 'discord', label: 'Discord' },
  { value: 'telegram', label: 'Telegram' },
  { value: 'generic', label: 'Generic (HTTP)' },
];

const WEBHOOK_EVENTS = [
  { value: 'agent_new', label: 'New Agent' },
  { value: 'agent_dead', label: 'Agent Dead' },
  { value: 'task_complete', label: 'Task Complete' },
  { value: 'credential_found', label: 'Credential Found' },
];

const TYPE_COLORS: Record<string, string> = {
  slack: '#4A154B',
  discord: '#5865F2',
  telegram: '#0088cc',
  generic: '#666',
};

export default function WebhookPanel() {
  const { webhooks, fetch, add, remove, toggle, test } = useWebhookStore();

  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState('');
  const [formType, setFormType] = useState('slack');
  const [formUrl, setFormUrl] = useState('');
  const [formEvents, setFormEvents] = useState<string[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  useEffect(() => {
    fetch();
  }, [fetch]);

  const resetForm = () => {
    setFormName('');
    setFormType('slack');
    setFormUrl('');
    setFormEvents([]);
    setError(null);
  };

  const handleToggleEvent = (event: string) => {
    setFormEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]
    );
  };

  const handleSubmit = async () => {
    if (!formName.trim()) {
      setError('Name is required');
      return;
    }
    if (!formUrl.trim()) {
      setError('URL is required');
      return;
    }
    if (formEvents.length === 0) {
      setError('Select at least one event');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      await add({
        name: formName.trim(),
        type: formType,
        url: formUrl.trim(),
        events: formEvents,
        active: true,
      });
      resetForm();
      setShowForm(false);
    } catch (err: any) {
      setError(err.message || 'Failed to add webhook');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTest = async (id: string) => {
    setTestingId(id);
    try {
      await test(id);
    } catch {
      // Test failures are expected sometimes
    } finally {
      setTimeout(() => setTestingId(null), 1500);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await remove(id);
      setDeleteConfirmId(null);
    } catch (err: any) {
      setError(err.message || 'Failed to delete webhook');
    }
  };

  // ── Styles ──────────────────────────────────────────────────

  const containerStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    background: '#0a0a0a',
    color: '#e0e0e0',
  };

  const toolbarStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 12px',
    borderBottom: '1px solid #222',
    background: '#111',
    flexShrink: 0,
  };

  const btnStyle: React.CSSProperties = {
    padding: '4px 12px',
    background: '#1a1a1a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    cursor: 'pointer',
    fontSize: '12px',
    fontFamily: 'inherit',
  };

  const btnAccentStyle: React.CSSProperties = {
    ...btnStyle,
    background: '#cc0000',
    borderColor: '#cc0000',
    color: '#fff',
  };

  const btnDangerStyle: React.CSSProperties = {
    ...btnStyle,
    color: '#cc0000',
    borderColor: '#440000',
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '6px 10px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '12px',
    fontFamily: 'inherit',
    outline: 'none',
    boxSizing: 'border-box',
  };

  const selectStyle: React.CSSProperties = {
    ...inputStyle,
    cursor: 'pointer',
    appearance: 'none',
    backgroundImage:
      'url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2712%27 height=%278%27%3E%3Cpath fill=%27%23888%27 d=%27M6 8L0 0h12z%27/%3E%3C/svg%3E")',
    backgroundRepeat: 'no-repeat',
    backgroundPosition: 'right 10px center',
    paddingRight: '30px',
  };

  const tableStyle: React.CSSProperties = {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: '12px',
  };

  const thStyle: React.CSSProperties = {
    textAlign: 'left',
    padding: '8px 10px',
    borderBottom: '1px solid #222',
    color: '#666',
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    fontWeight: 600,
    background: '#0d0d0d',
  };

  const tdStyle: React.CSSProperties = {
    padding: '8px 10px',
    borderBottom: '1px solid #1a1a1a',
  };

  const formContainerStyle: React.CSSProperties = {
    padding: '14px 16px',
    background: '#0d0d0d',
    borderBottom: '1px solid #222',
    flexShrink: 0,
  };

  const fieldStyle: React.CSSProperties = {
    marginBottom: '10px',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: '10px',
    color: '#666',
    marginBottom: '4px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    fontFamily: 'monospace',
  };

  const checkboxRowStyle: React.CSSProperties = {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '10px',
    marginTop: '4px',
  };

  const checkboxLabelStyle = (checked: boolean): React.CSSProperties => ({
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    padding: '3px 8px',
    background: checked ? '#cc000022' : '#1a1a1a',
    border: `1px solid ${checked ? '#cc0000' : '#333'}`,
    borderRadius: '3px',
    cursor: 'pointer',
    fontSize: '11px',
    color: checked ? '#cc0000' : '#888',
    transition: 'all 0.15s',
  });

  const typeBadge = (type: string): React.CSSProperties => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '3px',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    background: (TYPE_COLORS[type] || '#444') + '33',
    color: TYPE_COLORS[type] || '#888',
    border: `1px solid ${(TYPE_COLORS[type] || '#444')}66`,
  });

  const toggleStyle = (active: boolean): React.CSSProperties => ({
    width: '36px',
    height: '18px',
    borderRadius: '9px',
    background: active ? '#cc0000' : '#333',
    position: 'relative',
    cursor: 'pointer',
    transition: 'background 0.2s',
    border: 'none',
    padding: 0,
    flexShrink: 0,
  });

  const toggleKnobStyle = (active: boolean): React.CSSProperties => ({
    position: 'absolute',
    top: '2px',
    left: active ? '20px' : '2px',
    width: '14px',
    height: '14px',
    borderRadius: '50%',
    background: '#e0e0e0',
    transition: 'left 0.2s',
  });

  const emptyStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    color: '#444',
    fontSize: '14px',
    gap: '8px',
  };

  // ── Render ──────────────────────────────────────────────────

  return (
    <div style={containerStyle}>
      {/* Toolbar */}
      <div style={toolbarStyle}>
        <span style={{ fontSize: '13px', fontWeight: 600, color: '#cc0000' }}>
          Webhooks
        </span>
        <span style={{ fontSize: '11px', color: '#555' }}>
          ({webhooks.length} configured)
        </span>
        <div style={{ flex: 1 }} />
        <button
          style={showForm ? btnStyle : btnAccentStyle}
          onClick={() => {
            if (showForm) resetForm();
            setShowForm(!showForm);
          }}
        >
          {showForm ? 'Cancel' : 'Add Webhook'}
        </button>
        <button style={btnStyle} onClick={fetch}>
          Refresh
        </button>
      </div>

      {/* Error */}
      {error && (
        <div
          style={{
            padding: '6px 12px',
            background: '#1a0000',
            borderBottom: '1px solid #330000',
            color: '#cc0000',
            fontSize: '11px',
            flexShrink: 0,
          }}
        >
          {error}
        </div>
      )}

      {/* Add Form */}
      {showForm && (
        <div style={formContainerStyle}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div style={fieldStyle}>
              <label style={labelStyle}>Name</label>
              <input
                type="text"
                placeholder="My Webhook"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                style={inputStyle}
                autoFocus
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Type</label>
              <select
                style={selectStyle}
                value={formType}
                onChange={(e) => setFormType(e.target.value)}
              >
                {WEBHOOK_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div style={fieldStyle}>
            <label style={labelStyle}>URL</label>
            <input
              type="text"
              placeholder="https://hooks.slack.com/services/..."
              value={formUrl}
              onChange={(e) => setFormUrl(e.target.value)}
              style={inputStyle}
              onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
            />
          </div>
          <div style={fieldStyle}>
            <label style={labelStyle}>Events</label>
            <div style={checkboxRowStyle}>
              {WEBHOOK_EVENTS.map((ev) => (
                <label
                  key={ev.value}
                  style={checkboxLabelStyle(formEvents.includes(ev.value))}
                  onClick={() => handleToggleEvent(ev.value)}
                >
                  <span style={{ fontFamily: 'monospace' }}>
                    {formEvents.includes(ev.value) ? '[x]' : '[ ]'}
                  </span>
                  {ev.label}
                </label>
              ))}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
            <button
              style={btnAccentStyle}
              onClick={handleSubmit}
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Adding...' : 'Add Webhook'}
            </button>
          </div>
        </div>
      )}

      {/* Webhook Table */}
      {webhooks.length === 0 ? (
        <div style={emptyStyle}>
          <span style={{ fontSize: '32px', opacity: 0.3 }}>[~]</span>
          <span>No webhooks configured</span>
          <span style={{ fontSize: '11px', color: '#333' }}>
            Add a webhook to receive notifications for framework events
          </span>
        </div>
      ) : (
        <div style={{ flex: 1, overflow: 'auto' }}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Name</th>
                <th style={thStyle}>Type</th>
                <th style={thStyle}>URL</th>
                <th style={thStyle}>Events</th>
                <th style={thStyle}>Active</th>
                <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map((wh) => (
                <tr
                  key={wh.id}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = '#111'; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent'; }}
                >
                  <td style={{ ...tdStyle, fontWeight: 600 }}>{wh.name}</td>
                  <td style={tdStyle}>
                    <span style={typeBadge(wh.type)}>{wh.type}</span>
                  </td>
                  <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: '11px', color: '#888', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {wh.url}
                  </td>
                  <td style={tdStyle}>
                    <div style={{ display: 'flex', gap: '3px', flexWrap: 'wrap' }}>
                      {wh.events.map((ev) => (
                        <span
                          key={ev}
                          style={{
                            padding: '1px 5px',
                            background: '#1a1a1a',
                            borderRadius: '2px',
                            fontSize: '9px',
                            color: '#888',
                            border: '1px solid #222',
                          }}
                        >
                          {ev}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td style={tdStyle}>
                    <button
                      style={toggleStyle(wh.active)}
                      onClick={() => toggle(wh.id, !wh.active)}
                      title={wh.active ? 'Disable' : 'Enable'}
                    >
                      <div style={toggleKnobStyle(wh.active)} />
                    </button>
                  </td>
                  <td style={{ ...tdStyle, textAlign: 'right' }}>
                    <div style={{ display: 'flex', gap: '4px', justifyContent: 'flex-end' }}>
                      <button
                        style={{ ...btnStyle, fontSize: '11px', padding: '2px 8px' }}
                        onClick={() => handleTest(wh.id)}
                        disabled={testingId === wh.id}
                      >
                        {testingId === wh.id ? 'Sent!' : 'Test'}
                      </button>
                      {deleteConfirmId === wh.id ? (
                        <>
                          <button
                            style={{ ...btnDangerStyle, fontSize: '11px', padding: '2px 8px' }}
                            onClick={() => handleDelete(wh.id)}
                          >
                            Confirm
                          </button>
                          <button
                            style={{ ...btnStyle, fontSize: '11px', padding: '2px 8px' }}
                            onClick={() => setDeleteConfirmId(null)}
                          >
                            No
                          </button>
                        </>
                      ) : (
                        <button
                          style={{ ...btnDangerStyle, fontSize: '11px', padding: '2px 8px' }}
                          onClick={() => setDeleteConfirmId(wh.id)}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
