// ═══════════════════════════════════════════════════════════════
//  RTLC2 Auto-Task Rules Panel
//  Manages auto-task rules that execute on new agent checkins.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect } from 'react';
import { useAutoTaskStore } from '../../store/autoTaskStore';

const OS_OPTIONS = [
  { value: '', label: 'Any OS' },
  { value: 'windows', label: 'Windows' },
  { value: 'linux', label: 'Linux' },
  { value: 'macos', label: 'macOS' },
];

const ARCH_OPTIONS = [
  { value: '', label: 'Any Arch' },
  { value: 'x64', label: 'x64' },
  { value: 'x86', label: 'x86' },
  { value: 'arm64', label: 'ARM64' },
];

export default function AutoTaskPanel() {
  const { rules, fetch, add, remove, toggle } = useAutoTaskStore();

  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState('');
  const [formCommand, setFormCommand] = useState('');
  const [formOs, setFormOs] = useState('');
  const [formArch, setFormArch] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  useEffect(() => {
    fetch();
  }, [fetch]);

  const resetForm = () => {
    setFormName('');
    setFormCommand('');
    setFormOs('');
    setFormArch('');
    setError(null);
  };

  const handleSubmit = async () => {
    if (!formName.trim()) {
      setError('Name is required');
      return;
    }
    if (!formCommand.trim()) {
      setError('Task command is required');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      // Parse the command to determine task_type and data
      const parts = formCommand.trim().split(/\s+/);
      const taskType = parts[0] || '';
      const data = parts.slice(1).join(' ');

      await add({
        name: formName.trim(),
        task_type: taskType,
        data,
        params: {},
        os_filter: formOs,
        arch_filter: formArch,
        active: true,
      });
      resetForm();
      setShowForm(false);
    } catch (err: any) {
      setError(err.message || 'Failed to add auto-task rule');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await remove(id);
      setDeleteConfirmId(null);
    } catch (err: any) {
      setError(err.message || 'Failed to delete rule');
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

  const filterBadge = (value: string): React.CSSProperties => ({
    display: 'inline-block',
    padding: '2px 6px',
    borderRadius: '3px',
    fontSize: '10px',
    fontWeight: 600,
    background: value ? '#1a1a1a' : 'transparent',
    border: value ? '1px solid #333' : '1px solid transparent',
    color: value ? '#888' : '#333',
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
          Auto-Task Rules
        </span>
        <span style={{ fontSize: '11px', color: '#555' }}>
          ({rules.length} rules)
        </span>
        <div style={{ flex: 1 }} />
        <button
          style={showForm ? btnStyle : btnAccentStyle}
          onClick={() => {
            if (showForm) resetForm();
            setShowForm(!showForm);
          }}
        >
          {showForm ? 'Cancel' : 'Add Rule'}
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
              <label style={labelStyle}>Rule Name</label>
              <input
                type="text"
                placeholder="Recon on checkin"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                style={inputStyle}
                autoFocus
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Task Command</label>
              <input
                type="text"
                placeholder="whoami"
                value={formCommand}
                onChange={(e) => setFormCommand(e.target.value)}
                style={{ ...inputStyle, fontFamily: '"Cascadia Code", "Fira Code", "Consolas", monospace' }}
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div style={fieldStyle}>
              <label style={labelStyle}>OS Filter</label>
              <select
                style={selectStyle}
                value={formOs}
                onChange={(e) => setFormOs(e.target.value)}
              >
                {OS_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Arch Filter</label>
              <select
                style={selectStyle}
                value={formArch}
                onChange={(e) => setFormArch(e.target.value)}
              >
                {ARCH_OPTIONS.map((a) => (
                  <option key={a.value} value={a.value}>{a.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
            <button
              style={btnAccentStyle}
              onClick={handleSubmit}
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Adding...' : 'Add Rule'}
            </button>
          </div>
        </div>
      )}

      {/* Rules Table */}
      {rules.length === 0 ? (
        <div style={emptyStyle}>
          <span style={{ fontSize: '32px', opacity: 0.3 }}>[A]</span>
          <span>No auto-task rules configured</span>
          <span style={{ fontSize: '11px', color: '#333' }}>
            Add rules to automatically execute tasks when new agents check in
          </span>
        </div>
      ) : (
        <div style={{ flex: 1, overflow: 'auto' }}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Name</th>
                <th style={thStyle}>Command</th>
                <th style={thStyle}>OS Filter</th>
                <th style={thStyle}>Arch Filter</th>
                <th style={thStyle}>Active</th>
                <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr
                  key={rule.id}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = '#111'; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent'; }}
                >
                  <td style={{ ...tdStyle, fontWeight: 600 }}>{rule.name}</td>
                  <td style={{ ...tdStyle, fontFamily: '"Cascadia Code", "Fira Code", "Consolas", monospace', fontSize: '11px', color: '#cc0000' }}>
                    {rule.task_type}{rule.data ? ` ${rule.data}` : ''}
                  </td>
                  <td style={tdStyle}>
                    <span style={filterBadge(rule.os_filter)}>
                      {rule.os_filter || 'any'}
                    </span>
                  </td>
                  <td style={tdStyle}>
                    <span style={filterBadge(rule.arch_filter)}>
                      {rule.arch_filter || 'any'}
                    </span>
                  </td>
                  <td style={tdStyle}>
                    <button
                      style={toggleStyle(rule.active)}
                      onClick={() => toggle(rule.id, !rule.active)}
                      title={rule.active ? 'Disable' : 'Enable'}
                    >
                      <div style={toggleKnobStyle(rule.active)} />
                    </button>
                  </td>
                  <td style={{ ...tdStyle, textAlign: 'right' }}>
                    {deleteConfirmId === rule.id ? (
                      <div style={{ display: 'flex', gap: '4px', justifyContent: 'flex-end' }}>
                        <button
                          style={{ ...btnDangerStyle, fontSize: '11px', padding: '2px 8px' }}
                          onClick={() => handleDelete(rule.id)}
                        >
                          Confirm
                        </button>
                        <button
                          style={{ ...btnStyle, fontSize: '11px', padding: '2px 8px' }}
                          onClick={() => setDeleteConfirmId(null)}
                        >
                          No
                        </button>
                      </div>
                    ) : (
                      <button
                        style={{ ...btnDangerStyle, fontSize: '11px', padding: '2px 8px' }}
                        onClick={() => setDeleteConfirmId(rule.id)}
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Status Bar */}
      <div
        style={{
          padding: '4px 12px',
          borderTop: '1px solid #222',
          background: '#111',
          fontSize: '10px',
          color: '#444',
          fontFamily: 'monospace',
          display: 'flex',
          justifyContent: 'space-between',
          flexShrink: 0,
        }}
      >
        <span>{rules.filter((r) => r.active).length} active rules</span>
        <span>{rules.length} total</span>
      </div>
    </div>
  );
}
