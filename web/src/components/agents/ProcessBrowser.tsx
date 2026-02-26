// ═══════════════════════════════════════════════════════════════
//  RTLC2 Remote Process Browser
//  Sortable process table with search/filter, context menu for
//  inject/migrate/kill, and AV/EDR highlighting.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef } from 'react';
import { useTaskStore } from '../../store/taskStore';
import { useAgentStore } from '../../store/agentStore';
import { api } from '../../api/client';
import type { ProcessEntry, TaskRequest } from '../../types';
import { TaskType, TaskStatus } from '../../types';

interface ProcessBrowserProps {
  agentId: string;
}

type SortField = keyof ProcessEntry;
type SortDir = 'asc' | 'desc';

interface ContextMenuState {
  x: number;
  y: number;
  process: ProcessEntry;
}

// ── Known AV/EDR process names ───────────────────────────────

const AV_EDR_PROCESSES = new Set([
  // Windows Defender
  'msmpeng.exe', 'mpcmdrun.exe', 'nissrv.exe', 'securityhealthservice.exe',
  'securityhealthsystray.exe', 'smartscreen.exe',
  // CrowdStrike
  'csfalconservice.exe', 'csfalconcontainer.exe', 'csagent.exe',
  // SentinelOne
  'sentinelagent.exe', 'sentinelctl.exe', 'sentinelservicehost.exe',
  'sentinelstaticengine.exe', 'sentinelhelper.exe',
  // Carbon Black
  'cb.exe', 'cbcomms.exe', 'cbdefense.exe', 'repux.exe', 'repmgr.exe',
  // Cylance
  'cylanceprotect.exe', 'cylancesvc.exe', 'cylanceui.exe',
  // Symantec / Broadcom
  'ccsvchst.exe', 'rtvscan.exe', 'smcgui.exe', 'smc.exe', 'snac.exe',
  // McAfee / Trellix
  'mcshield.exe', 'mfemms.exe', 'mfemactl.exe', 'masvc.exe',
  // Sophos
  'sophosfilescanner.exe', 'sophosui.exe', 'sspsvc.exe', 'savservice.exe',
  'sophoshealth.exe', 'sophoscleanup.exe',
  // Kaspersky
  'avp.exe', 'avpui.exe',
  // ESET
  'ekrn.exe', 'egui.exe', 'eguiproxy.exe',
  // Trend Micro
  'coreserviceshell.exe', 'pccntmon.exe', 'tmbmsrv.exe', 'ntrtscan.exe',
  // Elastic / Endgame
  'elastic-endpoint.exe', 'elastic-agent.exe', 'endgame.exe',
  // Cortex XDR (Palo Alto)
  'cyserver.exe', 'cytray.exe', 'traps.exe',
  // Microsoft Sysmon
  'sysmon.exe', 'sysmon64.exe',
  // ETW consumers / telemetry
  'mrt.exe',
]);

// Detect our own agent processes by matching PID
function isOurProcess(process: ProcessEntry, agentPid: number): boolean {
  return process.pid === agentPid;
}

function isAvEdr(name: string): boolean {
  return AV_EDR_PROCESSES.has(name.toLowerCase());
}

// ── Parse ps output ──────────────────────────────────────────

function parsePsOutput(raw: string): ProcessEntry[] {
  const processes: ProcessEntry[] = [];
  const lines = raw.trim().split('\n');

  for (const line of lines) {
    if (!line.trim()) continue;

    // Try tab-separated: PID\tName\tUser\tArch\tSession\tPPID\tPath
    const tabParts = line.split('\t');
    if (tabParts.length >= 3) {
      processes.push({
        pid: parseInt(tabParts[0], 10) || 0,
        name: tabParts[1]?.trim() || '',
        user: tabParts[2]?.trim() || '',
        arch: tabParts[3]?.trim() || '',
        session: parseInt(tabParts[4], 10) || 0,
        ppid: parseInt(tabParts[5], 10) || 0,
        path: tabParts[6]?.trim() || '',
      });
      continue;
    }

    // Space-separated fallback
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2 && !isNaN(parseInt(parts[0], 10))) {
      processes.push({
        pid: parseInt(parts[0], 10),
        name: parts[1] || '',
        user: parts[2] || '',
        arch: parts[3] || '',
        session: parseInt(parts[4], 10) || 0,
        ppid: parseInt(parts[5], 10) || 0,
        path: parts.slice(6).join(' '),
      });
    }
  }

  return processes;
}

// ── Component ────────────────────────────────────────────────

export default function ProcessBrowser({ agentId }: ProcessBrowserProps) {
  const { addEntry, sendCommand } = useTaskStore();
  const agents = useAgentStore((s) => s.agents);
  const agent = agents.find((a) => a.id === agentId);
  const agentPid = agent?.pid ?? 0;

  const [processes, setProcesses] = useState<ProcessEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<SortField>('pid');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Fetch Processes ────────────────────────────────────────

  const fetchProcesses = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const task: TaskRequest = {
        agent_id: agentId,
        type: TaskType.PS,
        data: btoa(''),
        params: {},
      };
      const res = await api.sendTask(task);
      addEntry(agentId, { type: 'info', text: `[ProcessBrowser] ps -> task ${res.task_id}` });

      // Poll for result
      let attempts = 0;
      const maxAttempts = 30;

      if (pollTimerRef.current) clearInterval(pollTimerRef.current);

      pollTimerRef.current = setInterval(async () => {
        attempts++;
        if (attempts > maxAttempts) {
          if (pollTimerRef.current) clearInterval(pollTimerRef.current);
          setError('Timed out waiting for process list');
          setIsLoading(false);
          return;
        }

        try {
          const result = await api.getTaskResult(res.task_id);
          if (result.status === TaskStatus.COMPLETE) {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            const output = result.output ? atob(result.output) : '';
            setProcesses(parsePsOutput(output));
            setIsLoading(false);
          } else if (result.status === TaskStatus.ERROR) {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            const errMsg = result.output ? atob(result.output) : 'Process listing failed';
            setError(errMsg);
            setIsLoading(false);
          }
        } catch {
          // Task not ready yet
        }
      }, 1000);
    } catch (err: any) {
      setError(err.message);
      setIsLoading(false);
    }
  }, [agentId, addEntry]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, []);

  // Initial load
  useEffect(() => {
    fetchProcesses();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Close context menu on click
  useEffect(() => {
    if (!contextMenu) return;
    const handler = () => setContextMenu(null);
    window.addEventListener('click', handler);
    return () => window.removeEventListener('click', handler);
  }, [contextMenu]);

  // ── Sorting & Filtering ────────────────────────────────────

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const filtered = processes.filter((p) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      p.name.toLowerCase().includes(q) ||
      p.user.toLowerCase().includes(q) ||
      String(p.pid).includes(q) ||
      p.path.toLowerCase().includes(q)
    );
  });

  const sorted = [...filtered].sort((a, b) => {
    const aVal = a[sortField];
    const bVal = b[sortField];
    let cmp: number;
    if (typeof aVal === 'number' && typeof bVal === 'number') {
      cmp = aVal - bVal;
    } else {
      cmp = String(aVal).localeCompare(String(bVal), undefined, { numeric: true });
    }
    return sortDir === 'asc' ? cmp : -cmp;
  });

  // ── Context Menu Actions ───────────────────────────────────

  const handleInject = (process: ProcessEntry) => {
    sendCommand(agentId, `inject ${process.pid}`);
    setContextMenu(null);
  };

  const handleMigrate = (process: ProcessEntry) => {
    if (!confirm(`Migrate to ${process.name} (PID ${process.pid})? This will move the agent to a new process.`)) return;
    sendCommand(agentId, `inject ${process.pid} migrate`);
    setContextMenu(null);
  };

  const handleKill = (process: ProcessEntry) => {
    if (!confirm(`Kill process ${process.name} (PID ${process.pid})?`)) return;
    sendCommand(agentId, `shell taskkill /F /PID ${process.pid}`);
    setContextMenu(null);
  };

  const handleContextMenu = (e: React.MouseEvent, process: ProcessEntry) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, process });
  };

  // ── Row Styling ────────────────────────────────────────────

  const rowClass = (process: ProcessEntry): string => {
    const classes: string[] = [];
    if (process.pid === selectedPid) classes.push('selected');
    return classes.join(' ');
  };

  const rowStyle = (process: ProcessEntry): React.CSSProperties => {
    if (isOurProcess(process, agentPid)) {
      return { borderLeft: '3px solid var(--green)' };
    }
    if (isAvEdr(process.name)) {
      return { borderLeft: '3px solid var(--red-primary)' };
    }
    return {};
  };

  const nameStyle = (process: ProcessEntry): React.CSSProperties => {
    if (isOurProcess(process, agentPid)) {
      return { color: 'var(--green)', fontWeight: 700 };
    }
    if (isAvEdr(process.name)) {
      return { color: 'var(--red-light)', fontWeight: 600 };
    }
    return {};
  };

  // ── Render ─────────────────────────────────────────────────

  const columns: { key: SortField; label: string; width?: string }[] = [
    { key: 'pid', label: 'PID', width: '70px' },
    { key: 'name', label: 'Name' },
    { key: 'user', label: 'User' },
    { key: 'arch', label: 'Arch', width: '60px' },
    { key: 'session', label: 'Session', width: '70px' },
    { key: 'ppid', label: 'PPID', width: '70px' },
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
        <button
          className="btn btn--small"
          onClick={fetchProcesses}
          disabled={isLoading}
        >
          {isLoading ? 'Loading...' : 'Refresh'}
        </button>

        {/* Search */}
        <div style={{ flex: 1 }}>
          <input
            className="input"
            style={{ height: '26px', fontSize: '12px' }}
            placeholder="Search by name, user, PID, or path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', gap: '12px', fontSize: '10px', color: 'var(--text-dim)', flexShrink: 0 }}>
          <span><span style={{ color: 'var(--green)', fontWeight: 700 }}>||</span> Our Process</span>
          <span><span style={{ color: 'var(--red-light)', fontWeight: 700 }}>||</span> AV/EDR</span>
        </div>
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

      {/* Loading */}
      {isLoading && (
        <div style={{
          padding: '6px 10px',
          background: 'var(--bg-tertiary)',
          borderBottom: '1px solid var(--border-primary)',
          color: 'var(--text-dim)',
          fontSize: '11px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          flexShrink: 0,
        }}>
          <div className="spinner" style={{ width: '14px', height: '14px', borderWidth: '1.5px' }} />
          Fetching process list...
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
            </tr>
          </thead>
          <tbody>
            {!isLoading && sorted.length === 0 ? (
              <tr>
                <td colSpan={columns.length} style={{ textAlign: 'center', color: 'var(--text-dark)', padding: '24px' }}>
                  {error ? 'Failed to fetch processes' : searchQuery ? 'No matching processes' : 'No processes'}
                </td>
              </tr>
            ) : (
              sorted.map((proc) => (
                <tr
                  key={proc.pid}
                  className={rowClass(proc)}
                  style={{ ...rowStyle(proc), cursor: 'pointer' }}
                  onClick={() => setSelectedPid(proc.pid)}
                  onContextMenu={(e) => handleContextMenu(e, proc)}
                >
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{proc.pid}</td>
                  <td style={nameStyle(proc)}>{proc.name}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{proc.user || '--'}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{proc.arch || '--'}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{proc.session}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{proc.ppid}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Status Bar */}
      <div style={{
        padding: '4px 10px',
        borderTop: '1px solid var(--border-primary)',
        background: 'var(--bg-tertiary)',
        fontSize: '10px',
        color: 'var(--text-dim)',
        fontFamily: 'var(--font-mono)',
        display: 'flex',
        justifyContent: 'space-between',
        flexShrink: 0,
      }}>
        <span>
          {filtered.length} processes
          {searchQuery && ` (filtered from ${processes.length})`}
        </span>
        <span>
          Agent PID: {agentPid}
          {' | '}
          AV/EDR detected: {processes.filter((p) => isAvEdr(p.name)).length}
        </span>
      </div>

      {/* Context Menu */}
      {contextMenu && (
        <div
          className="context-menu"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="context-menu__label">
            {contextMenu.process.name} (PID {contextMenu.process.pid})
          </div>
          <div className="context-menu__separator" />
          <div className="context-menu__item" onClick={() => handleInject(contextMenu.process)}>
            Inject Into Process
          </div>
          <div className="context-menu__item" onClick={() => handleMigrate(contextMenu.process)}>
            Migrate To Process
          </div>
          <div className="context-menu__separator" />
          <div className="context-menu__item context-menu__item--danger" onClick={() => handleKill(contextMenu.process)}>
            Kill Process
          </div>
          <div className="context-menu__separator" />
          <div
            className="context-menu__item"
            onClick={() => {
              navigator.clipboard.writeText(String(contextMenu.process.pid));
              setContextMenu(null);
            }}
          >
            Copy PID
          </div>
          <div
            className="context-menu__item"
            onClick={() => {
              navigator.clipboard.writeText(contextMenu.process.name);
              setContextMenu(null);
            }}
          >
            Copy Name
          </div>
        </div>
      )}
    </div>
  );
}
