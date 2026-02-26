// ═══════════════════════════════════════════════════════════════
//  RTLC2 Credential Panel
//  Aggregated credential viewer with filtering, search, CSV
//  export, and manual credential addition.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback } from 'react';
import { useCredentialStore } from '../../store/credentialStore';
import { CredentialType } from '../../types';
import type { Credential, CredentialTypeValue } from '../../types';

type SortField = keyof Credential;
type SortDir = 'asc' | 'desc';

interface AddCredentialForm {
  type: CredentialTypeValue;
  username: string;
  domain: string;
  value: string;
  source_agent_id: string;
  source_agent_hostname: string;
  note: string;
}

const EMPTY_FORM: AddCredentialForm = {
  type: CredentialType.NTLM,
  username: '',
  domain: '',
  value: '',
  source_agent_id: '',
  source_agent_hostname: 'Manual',
  note: '',
};

const TYPE_LABELS: Record<string, string> = {
  [CredentialType.NTLM]: 'NTLM Hash',
  [CredentialType.PLAINTEXT]: 'Plaintext',
  [CredentialType.TICKET]: 'Kerberos Ticket',
  [CredentialType.CERTIFICATE]: 'Certificate',
  [CredentialType.SSH_KEY]: 'SSH Key',
};

const TYPE_COLORS: Record<string, string> = {
  [CredentialType.NTLM]: 'var(--orange)',
  [CredentialType.PLAINTEXT]: 'var(--red-light)',
  [CredentialType.TICKET]: 'var(--cyan)',
  [CredentialType.CERTIFICATE]: 'var(--blue)',
  [CredentialType.SSH_KEY]: 'var(--green)',
};

export default function CredentialPanel() {
  const {
    isLoading,
    error,
    filters,
    fetch: fetchCredentials,
    addCredential,
    deleteCredential,
    setFilter,
    getFiltered,
    exportCSV,
  } = useCredentialStore();

  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [addForm, setAddForm] = useState<AddCredentialForm>(EMPTY_FORM);
  const [addLoading, setAddLoading] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set());

  // Initial fetch
  useEffect(() => {
    fetchCredentials();
  }, [fetchCredentials]);

  // ── Sorting ────────────────────────────────────────────────

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const filtered = getFiltered();
  const sorted = [...filtered].sort((a, b) => {
    const aVal = String(a[sortField] ?? '');
    const bVal = String(b[sortField] ?? '');
    const cmp = aVal.localeCompare(bVal, undefined, { numeric: true });
    return sortDir === 'asc' ? cmp : -cmp;
  });

  // ── Add Credential ─────────────────────────────────────────

  const handleAdd = useCallback(async () => {
    if (!addForm.username.trim() || !addForm.value.trim()) {
      setAddError('Username and value are required');
      return;
    }

    setAddLoading(true);
    setAddError(null);
    try {
      await addCredential(addForm);
      setShowAddDialog(false);
      setAddForm(EMPTY_FORM);
    } catch (err: any) {
      setAddError(err.message);
    } finally {
      setAddLoading(false);
    }
  }, [addForm, addCredential]);

  // ── Reveal/Hide Value ──────────────────────────────────────

  const toggleReveal = (id: string) => {
    setRevealedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const maskValue = (value: string, id: string): string => {
    if (revealedIds.has(id)) return value;
    if (value.length <= 8) return '*'.repeat(value.length);
    return value.slice(0, 4) + '*'.repeat(Math.min(value.length - 4, 16)) + value.slice(-4);
  };

  // ── Delete ─────────────────────────────────────────────────

  const handleDelete = (cred: Credential) => {
    if (!confirm(`Delete credential for ${cred.domain}\\${cred.username}?`)) return;
    deleteCredential(cred.id);
  };

  // ── Render ─────────────────────────────────────────────────

  const columns: { key: SortField; label: string; width?: string }[] = [
    { key: 'type', label: 'Type', width: '110px' },
    { key: 'username', label: 'Username' },
    { key: 'domain', label: 'Domain', width: '140px' },
    { key: 'value', label: 'Value' },
    { key: 'source_agent_hostname', label: 'Source', width: '120px' },
    { key: 'timestamp', label: 'Timestamp', width: '160px' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg-secondary)' }}>
      {/* Toolbar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '6px 10px',
        borderBottom: '1px solid var(--border-primary)',
        background: 'var(--bg-tertiary)',
        flexShrink: 0,
      }}>
        <button className="btn btn--small" onClick={fetchCredentials} disabled={isLoading}>
          {isLoading ? 'Loading...' : 'Refresh'}
        </button>
        <button className="btn btn--small btn--primary" onClick={() => setShowAddDialog(true)}>
          + Add
        </button>
        <button className="btn btn--small" onClick={exportCSV} disabled={filtered.length === 0}>
          Export CSV
        </button>

        <div className="context-menu__separator" style={{ width: '1px', height: '20px', margin: '0 4px', background: 'var(--border-secondary)' }} />

        {/* Type Filter */}
        <select
          className="select"
          style={{ width: '140px', height: '26px', fontSize: '11px' }}
          value={filters.type}
          onChange={(e) => setFilter({ type: e.target.value as CredentialTypeValue | 'all' })}
        >
          <option value="all">All Types</option>
          {Object.entries(CredentialType).map(([label, value]) => (
            <option key={value} value={value}>{TYPE_LABELS[value] || label}</option>
          ))}
        </select>

        {/* Search */}
        <div style={{ flex: 1 }}>
          <input
            className="input"
            style={{ height: '26px', fontSize: '12px' }}
            placeholder="Search username, domain, value..."
            value={filters.search}
            onChange={(e) => setFilter({ search: e.target.value })}
          />
        </div>

        {/* Count */}
        <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
          {filtered.length} creds
        </span>
      </div>

      {/* Error */}
      {error && (
        <div style={{
          padding: '6px 10px',
          background: 'var(--red-bg)',
          borderBottom: '1px solid var(--red-dark)',
          color: 'var(--red-light)',
          fontSize: '11px',
          flexShrink: 0,
        }}>
          {error}
        </div>
      )}

      {/* Table */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="rtl-table">
          <thead>
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  className={sortField === col.key ? 'sorted' : ''}
                  style={{ width: col.width }}
                  onClick={() => handleSort(col.key)}
                >
                  {col.label}
                  {sortField === col.key && (
                    <span style={{ marginLeft: '4px', fontSize: '10px' }}>
                      {sortDir === 'asc' ? '\u25B2' : '\u25BC'}
                    </span>
                  )}
                </th>
              ))}
              <th style={{ width: '80px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {!isLoading && sorted.length === 0 ? (
              <tr>
                <td colSpan={columns.length + 1} style={{ textAlign: 'center', color: 'var(--text-dark)', padding: '24px' }}>
                  {filters.search || filters.type !== 'all'
                    ? 'No credentials match the current filters'
                    : 'No credentials collected yet'}
                </td>
              </tr>
            ) : (
              sorted.map((cred) => (
                <tr key={cred.id}>
                  <td>
                    <span style={{
                      display: 'inline-block',
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-sm)',
                      background: 'var(--bg-input)',
                      border: `1px solid ${TYPE_COLORS[cred.type] || 'var(--border-secondary)'}`,
                      color: TYPE_COLORS[cred.type] || 'var(--text-muted)',
                      fontSize: '10px',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                    }}>
                      {TYPE_LABELS[cred.type] || cred.type}
                    </span>
                  </td>
                  <td style={{ fontWeight: 600 }}>{cred.username}</td>
                  <td style={{ color: 'var(--text-muted)' }}>{cred.domain || '--'}</td>
                  <td>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        cursor: 'pointer',
                        color: revealedIds.has(cred.id) ? 'var(--text-primary)' : 'var(--text-dim)',
                        userSelect: revealedIds.has(cred.id) ? 'text' : 'none',
                      }}
                      onClick={() => toggleReveal(cred.id)}
                      title={revealedIds.has(cred.id) ? 'Click to hide' : 'Click to reveal'}
                    >
                      {maskValue(cred.value, cred.id)}
                    </span>
                  </td>
                  <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {cred.source_agent_hostname || '--'}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                    {cred.timestamp}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button
                        className="btn btn--small"
                        onClick={() => navigator.clipboard.writeText(cred.value)}
                        title="Copy value"
                        style={{ padding: '2px 6px', fontSize: '10px' }}
                      >
                        Copy
                      </button>
                      <button
                        className="btn btn--small btn--danger"
                        onClick={() => handleDelete(cred)}
                        title="Delete"
                        style={{ padding: '2px 6px', fontSize: '10px' }}
                      >
                        Del
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add Credential Dialog */}
      {showAddDialog && (
        <div className="dialog-overlay" onClick={() => setShowAddDialog(false)}>
          <div className="dialog" style={{ minWidth: '480px' }} onClick={(e) => e.stopPropagation()}>
            <div className="dialog__header">
              <div className="dialog__title">Add Credential</div>
              <button className="dialog__close" onClick={() => setShowAddDialog(false)}>x</button>
            </div>
            <div className="dialog__body">
              {addError && (
                <div style={{
                  padding: '8px 12px',
                  background: 'var(--red-bg)',
                  border: '1px solid var(--red-dark)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--red-light)',
                  fontSize: '12px',
                  marginBottom: '12px',
                }}>
                  {addError}
                </div>
              )}

              <div className="group-box">
                <div className="group-box__title">Credential Details</div>
                <div className="group-box__grid">
                  <label className="group-box__label">Type</label>
                  <select
                    className="select"
                    value={addForm.type}
                    onChange={(e) => setAddForm((f) => ({ ...f, type: e.target.value as CredentialTypeValue }))}
                  >
                    {Object.entries(CredentialType).map(([label, value]) => (
                      <option key={value} value={value}>{TYPE_LABELS[value] || label}</option>
                    ))}
                  </select>

                  <label className="group-box__label">Username</label>
                  <input
                    className="input"
                    placeholder="e.g., administrator"
                    value={addForm.username}
                    onChange={(e) => setAddForm((f) => ({ ...f, username: e.target.value }))}
                  />

                  <label className="group-box__label">Domain</label>
                  <input
                    className="input"
                    placeholder="e.g., CORP.LOCAL"
                    value={addForm.domain}
                    onChange={(e) => setAddForm((f) => ({ ...f, domain: e.target.value }))}
                  />

                  <label className="group-box__label">Value</label>
                  <input
                    className="input"
                    placeholder={addForm.type === 'ntlm' ? 'NTLM hash' : addForm.type === 'plaintext' ? 'Password' : 'Value'}
                    value={addForm.value}
                    onChange={(e) => setAddForm((f) => ({ ...f, value: e.target.value }))}
                    style={{ fontFamily: 'var(--font-mono)' }}
                  />

                  <label className="group-box__label">Note</label>
                  <input
                    className="input"
                    placeholder="Optional note"
                    value={addForm.note}
                    onChange={(e) => setAddForm((f) => ({ ...f, note: e.target.value }))}
                  />
                </div>
              </div>
            </div>
            <div className="dialog__footer">
              <button className="btn" onClick={() => setShowAddDialog(false)}>Cancel</button>
              <button
                className="btn btn--primary"
                onClick={handleAdd}
                disabled={addLoading || !addForm.username.trim() || !addForm.value.trim()}
              >
                {addLoading ? 'Adding...' : 'Add Credential'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
