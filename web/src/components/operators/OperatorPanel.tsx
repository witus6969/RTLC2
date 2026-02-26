// ═══════════════════════════════════════════════════════════════
//  RTLC2 Operator Management Panel (Admin Only)
//  Create, edit roles, reset passwords, delete operators, manage sessions.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect } from 'react';
import { useOperatorStore } from '../../store/operatorStore';
import { useAuthStore } from '../../store/authStore';

const ROLE_COLORS: Record<string, string> = {
  admin: '#cc0000',
  operator: '#cc9900',
  viewer: '#0088cc',
};

export default function OperatorPanel() {
  const {
    operators,
    sessions,
    loading,
    fetch,
    create,
    updateRole,
    resetPassword,
    remove,
    fetchSessions,
    kickSession,
  } = useOperatorStore();
  const currentRole = useAuthStore((s) => s.role);

  const [showCreateForm, setShowCreateForm] = useState(false);
  const [formUsername, setFormUsername] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formRole, setFormRole] = useState('operator');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [editRoleId, setEditRoleId] = useState<string | null>(null);
  const [editRoleValue, setEditRoleValue] = useState('');
  const [resetPwId, setResetPwId] = useState<string | null>(null);
  const [resetPwValue, setResetPwValue] = useState('');
  const [showSessions, setShowSessions] = useState(false);

  useEffect(() => {
    fetch();
    fetchSessions();
  }, [fetch, fetchSessions]);

  // Guard: only admins should see this panel
  if (currentRole !== 'admin') {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100%', color: '#cc0000', fontSize: '14px', background: '#0a0a0a',
      }}>
        Admin access required
      </div>
    );
  }

  const handleCreate = async () => {
    if (!formUsername.trim()) {
      setError('Username is required');
      return;
    }
    if (!formPassword.trim()) {
      setError('Password is required');
      return;
    }
    setIsSubmitting(true);
    setError(null);
    try {
      await create(formUsername.trim(), formPassword, formRole);
      setFormUsername('');
      setFormPassword('');
      setFormRole('operator');
      setShowCreateForm(false);
    } catch (err: any) {
      setError(err.message || 'Failed to create operator');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUpdateRole = async () => {
    if (!editRoleId || !editRoleValue) return;
    try {
      await updateRole(editRoleId, editRoleValue);
      setEditRoleId(null);
      setEditRoleValue('');
    } catch (err: any) {
      setError(err.message || 'Failed to update role');
    }
  };

  const handleResetPassword = async () => {
    if (!resetPwId || !resetPwValue.trim()) return;
    try {
      await resetPassword(resetPwId, resetPwValue);
      setResetPwId(null);
      setResetPwValue('');
    } catch (err: any) {
      setError(err.message || 'Failed to reset password');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await remove(id);
      setDeleteConfirmId(null);
    } catch (err: any) {
      setError(err.message || 'Failed to delete operator');
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

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: '10px',
    color: '#666',
    marginBottom: '4px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    fontFamily: 'monospace',
  };

  const fieldStyle: React.CSSProperties = {
    marginBottom: '10px',
  };

  const roleBadge = (role: string): React.CSSProperties => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '3px',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    background: (ROLE_COLORS[role] || '#444') + '22',
    color: ROLE_COLORS[role] || '#888',
    border: `1px solid ${(ROLE_COLORS[role] || '#444')}44`,
  });

  const onlineDot = (isOnline: boolean): React.CSSProperties => ({
    display: 'inline-block',
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    background: isOnline ? '#00cc44' : '#444',
    marginRight: '6px',
  });

  // ── Render ──────────────────────────────────────────────────

  return (
    <div style={containerStyle}>
      {/* Toolbar */}
      <div style={toolbarStyle}>
        <span style={{ fontSize: '13px', fontWeight: 600, color: '#cc0000' }}>
          Operator Management
        </span>
        <span style={{ fontSize: '11px', color: '#555' }}>
          ({operators.length} operators)
        </span>
        <div style={{ flex: 1 }} />
        <button
          style={showSessions ? btnAccentStyle : btnStyle}
          onClick={() => { setShowSessions(!showSessions); if (!showSessions) fetchSessions(); }}
        >
          {showSessions ? 'Hide Sessions' : 'Active Sessions'}
        </button>
        <button
          style={showCreateForm ? btnStyle : btnAccentStyle}
          onClick={() => {
            if (showCreateForm) {
              setFormUsername('');
              setFormPassword('');
              setFormRole('operator');
            }
            setShowCreateForm(!showCreateForm);
          }}
        >
          {showCreateForm ? 'Cancel' : 'Create Operator'}
        </button>
        <button style={btnStyle} onClick={() => { fetch(); fetchSessions(); }} disabled={loading}>
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
          onClick={() => setError(null)}
        >
          {error}
        </div>
      )}

      {/* Create Form */}
      {showCreateForm && (
        <div style={formContainerStyle}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px' }}>
            <div style={fieldStyle}>
              <label style={labelStyle}>Username</label>
              <input
                type="text"
                placeholder="newoperator"
                value={formUsername}
                onChange={(e) => setFormUsername(e.target.value)}
                style={inputStyle}
                autoFocus
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Password</label>
              <input
                type="password"
                placeholder="Password"
                value={formPassword}
                onChange={(e) => setFormPassword(e.target.value)}
                style={inputStyle}
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Role</label>
              <select
                style={selectStyle}
                value={formRole}
                onChange={(e) => setFormRole(e.target.value)}
              >
                <option value="admin">Admin</option>
                <option value="operator">Operator</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
            <button
              style={btnAccentStyle}
              onClick={handleCreate}
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Creating...' : 'Create Operator'}
            </button>
          </div>
        </div>
      )}

      {/* Active Sessions */}
      {showSessions && (
        <div style={{ borderBottom: '1px solid #222', flexShrink: 0 }}>
          <div style={{ padding: '6px 12px', fontSize: '10px', color: '#666', textTransform: 'uppercase', background: '#0d0d0d', borderBottom: '1px solid #1a1a1a' }}>
            Active Sessions ({sessions.length})
          </div>
          {sessions.length === 0 ? (
            <div style={{ padding: '12px', fontSize: '12px', color: '#444', textAlign: 'center' }}>
              No active sessions
            </div>
          ) : (
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={thStyle}>Token Prefix</th>
                  <th style={thStyle}>Username</th>
                  <th style={thStyle}>Role</th>
                  <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <tr
                    key={s.token_prefix}
                    onMouseEnter={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = '#111'; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent'; }}
                  >
                    <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: '11px' }}>{s.token_prefix}...</td>
                    <td style={tdStyle}>{s.username}</td>
                    <td style={tdStyle}><span style={roleBadge(s.role)}>{s.role}</span></td>
                    <td style={{ ...tdStyle, textAlign: 'right' }}>
                      <button
                        style={{ ...btnDangerStyle, fontSize: '11px', padding: '2px 8px' }}
                        onClick={() => kickSession(s.token_prefix)}
                      >
                        Kick
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Operator Table */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={thStyle}>Status</th>
              <th style={thStyle}>Username</th>
              <th style={thStyle}>Role</th>
              <th style={thStyle}>Last Login</th>
              <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {operators.map((op) => (
              <tr
                key={op.id}
                onMouseEnter={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = '#111'; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent'; }}
              >
                <td style={tdStyle}>
                  <span style={onlineDot(op.online)} />
                  {op.online ? 'Online' : 'Offline'}
                </td>
                <td style={{ ...tdStyle, fontWeight: 600 }}>{op.username}</td>
                <td style={tdStyle}>
                  {editRoleId === op.id ? (
                    <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                      <select
                        style={{ ...selectStyle, width: '100px', padding: '2px 6px' }}
                        value={editRoleValue}
                        onChange={(e) => setEditRoleValue(e.target.value)}
                      >
                        <option value="admin">Admin</option>
                        <option value="operator">Operator</option>
                        <option value="viewer">Viewer</option>
                      </select>
                      <button
                        style={{ ...btnAccentStyle, fontSize: '10px', padding: '2px 6px' }}
                        onClick={handleUpdateRole}
                      >
                        Save
                      </button>
                      <button
                        style={{ ...btnStyle, fontSize: '10px', padding: '2px 6px' }}
                        onClick={() => { setEditRoleId(null); setEditRoleValue(''); }}
                      >
                        X
                      </button>
                    </div>
                  ) : (
                    <span style={roleBadge(op.role)}>{op.role}</span>
                  )}
                </td>
                <td style={{ ...tdStyle, fontSize: '11px', color: '#888', fontFamily: 'monospace' }}>
                  {op.last_login || 'Never'}
                </td>
                <td style={{ ...tdStyle, textAlign: 'right' }}>
                  <div style={{ display: 'flex', gap: '4px', justifyContent: 'flex-end' }}>
                    {/* Edit Role */}
                    {editRoleId !== op.id && (
                      <button
                        style={{ ...btnStyle, fontSize: '11px', padding: '2px 8px' }}
                        onClick={() => { setEditRoleId(op.id); setEditRoleValue(op.role); }}
                      >
                        Role
                      </button>
                    )}
                    {/* Reset Password */}
                    {resetPwId === op.id ? (
                      <div style={{ display: 'flex', gap: '3px', alignItems: 'center' }}>
                        <input
                          type="password"
                          placeholder="New password"
                          value={resetPwValue}
                          onChange={(e) => setResetPwValue(e.target.value)}
                          style={{ ...inputStyle, width: '110px', padding: '2px 6px', fontSize: '11px' }}
                          autoFocus
                        />
                        <button
                          style={{ ...btnAccentStyle, fontSize: '10px', padding: '2px 6px' }}
                          onClick={handleResetPassword}
                        >
                          Set
                        </button>
                        <button
                          style={{ ...btnStyle, fontSize: '10px', padding: '2px 6px' }}
                          onClick={() => { setResetPwId(null); setResetPwValue(''); }}
                        >
                          X
                        </button>
                      </div>
                    ) : (
                      <button
                        style={{ ...btnStyle, fontSize: '11px', padding: '2px 8px' }}
                        onClick={() => setResetPwId(op.id)}
                      >
                        Password
                      </button>
                    )}
                    {/* Delete */}
                    {deleteConfirmId === op.id ? (
                      <>
                        <button
                          style={{ ...btnDangerStyle, fontSize: '11px', padding: '2px 8px' }}
                          onClick={() => handleDelete(op.id)}
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
                        onClick={() => setDeleteConfirmId(op.id)}
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
    </div>
  );
}
