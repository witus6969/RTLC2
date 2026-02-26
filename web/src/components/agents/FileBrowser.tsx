// ═══════════════════════════════════════════════════════════════
//  RTLC2 Remote File Browser
//  Tree view with breadcrumb navigation, sortable columns,
//  context menu actions, and upload capability.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef } from 'react';
import { useTaskStore } from '../../store/taskStore';
import { api } from '../../api/client';
import type { FileEntry, TaskRequest } from '../../types';
import { TaskType, TaskStatus } from '../../types';

interface FileBrowserProps {
  agentId: string;
}

type SortField = 'name' | 'size' | 'modified' | 'type';
type SortDir = 'asc' | 'desc';

interface ContextMenuState {
  x: number;
  y: number;
  entry: FileEntry;
}

// ── Helpers ──────────────────────────────────────────────────

function formatSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function parseLsOutput(raw: string): FileEntry[] {
  // Parse the output of the agent's ls command
  // Expected format per line: <type> <perms> <size> <modified> <name>
  // Or simpler: <name>\t<size>\t<modified>\t<type>\t<permissions>
  const entries: FileEntry[] = [];
  const lines = raw.trim().split('\n');

  for (const line of lines) {
    if (!line.trim()) continue;

    // Try tab-separated format first
    const tabParts = line.split('\t');
    if (tabParts.length >= 4) {
      entries.push({
        name: tabParts[0].trim(),
        size: parseInt(tabParts[1], 10) || 0,
        modified: tabParts[2]?.trim() || '',
        type: tabParts[3]?.trim() === 'directory' || tabParts[3]?.trim() === 'dir' ? 'directory' : 'file',
        permissions: tabParts[4]?.trim() || '',
      });
      continue;
    }

    // Fallback: try space-separated (simplified ls-like format)
    // drwxr-xr-x  4096  2024-01-01 12:00  dirname
    // -rw-r--r--  1234  2024-01-01 12:00  filename.txt
    const match = line.match(/^([d\-l][rwx\-]{9})\s+(\d+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+(.+)$/);
    if (match) {
      const [, perms, size, modified, name] = match;
      entries.push({
        name: name.trim(),
        size: parseInt(size, 10),
        modified,
        type: perms.startsWith('d') ? 'directory' : 'file',
        permissions: perms,
      });
      continue;
    }

    // Last resort: treat as a filename
    if (line.trim()) {
      entries.push({
        name: line.trim(),
        size: 0,
        modified: '',
        type: 'file',
        permissions: '',
      });
    }
  }

  return entries;
}

function joinPath(...parts: string[]): string {
  // Handle both Windows and Unix paths
  const joined = parts.join('/').replace(/\/+/g, '/');
  // If it looks like a Windows path, use backslash
  if (/^[A-Z]:/i.test(joined)) {
    return joined.replace(/\//g, '\\');
  }
  return joined;
}

function parentPath(path: string): string {
  // Handle both separators
  const normalized = path.replace(/\\/g, '/');
  const parts = normalized.split('/').filter(Boolean);
  if (parts.length <= 1) return normalized.startsWith('/') ? '/' : parts[0] || '/';
  parts.pop();
  const parent = parts.join('/');
  if (normalized.startsWith('/')) return '/' + parent;
  return parent;
}

function pathSegments(path: string): string[] {
  const normalized = path.replace(/\\/g, '/');
  return normalized.split('/').filter(Boolean);
}

// ── Component ────────────────────────────────────────────────

export default function FileBrowser({ agentId }: FileBrowserProps) {
  const { addEntry } = useTaskStore();

  const [currentPath, setCurrentPath] = useState('/');
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sortField, setSortField] = useState<SortField>('name');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [pathInput, setPathInput] = useState('');
  const [showPathEdit, setShowPathEdit] = useState(false);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Navigation ─────────────────────────────────────────────

  const listDirectory = useCallback(async (path: string) => {
    setIsLoading(true);
    setError(null);

    try {
      // Send ls task
      const task: TaskRequest = {
        agent_id: agentId,
        type: TaskType.LS,
        data: btoa(path),
        params: { path },
      };
      const res = await api.sendTask(task);
      addEntry(agentId, { type: 'info', text: `[FileBrowser] ls "${path}" -> task ${res.task_id}` });

      // Poll for result
      let attempts = 0;
      const maxAttempts = 30;

      if (pollTimerRef.current) clearInterval(pollTimerRef.current);

      pollTimerRef.current = setInterval(async () => {
        attempts++;
        if (attempts > maxAttempts) {
          if (pollTimerRef.current) clearInterval(pollTimerRef.current);
          setError('Timed out waiting for directory listing');
          setIsLoading(false);
          return;
        }

        try {
          const result = await api.getTaskResult(res.task_id);
          if (result.status === TaskStatus.COMPLETE) {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            const output = result.output ? atob(result.output) : '';
            const parsed = parseLsOutput(output);
            setEntries(parsed);
            setCurrentPath(path);
            setIsLoading(false);
          } else if (result.status === TaskStatus.ERROR) {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            const errMsg = result.output ? atob(result.output) : 'Directory listing failed';
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

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, []);

  // Initial load
  useEffect(() => {
    listDirectory(currentPath);
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps

  // Close context menu on click
  useEffect(() => {
    if (!contextMenu) return;
    const handler = () => setContextMenu(null);
    window.addEventListener('click', handler);
    return () => window.removeEventListener('click', handler);
  }, [contextMenu]);

  // ── Sorting ────────────────────────────────────────────────

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const sorted = [...entries].sort((a, b) => {
    // Directories always first
    if (a.type !== b.type) {
      return a.type === 'directory' ? -1 : 1;
    }

    let cmp = 0;
    switch (sortField) {
      case 'name':
        cmp = a.name.localeCompare(b.name, undefined, { numeric: true });
        break;
      case 'size':
        cmp = a.size - b.size;
        break;
      case 'modified':
        cmp = a.modified.localeCompare(b.modified);
        break;
      case 'type':
        cmp = a.type.localeCompare(b.type);
        break;
    }
    return sortDir === 'asc' ? cmp : -cmp;
  });

  // ── Actions ────────────────────────────────────────────────

  const navigateTo = (path: string) => {
    listDirectory(path);
  };

  const handleDoubleClick = (entry: FileEntry) => {
    if (entry.type === 'directory') {
      navigateTo(joinPath(currentPath, entry.name));
    }
  };

  const handleContextMenu = (e: React.MouseEvent, entry: FileEntry) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, entry });
  };

  const handleDownload = async (entry: FileEntry) => {
    const remotePath = joinPath(currentPath, entry.name);
    try {
      const task: TaskRequest = {
        agent_id: agentId,
        type: TaskType.DOWNLOAD,
        data: btoa(remotePath),
        params: { path: remotePath },
      };
      const res = await api.sendTask(task);
      addEntry(agentId, { type: 'info', text: `[FileBrowser] Download queued: ${remotePath} -> task ${res.task_id}` });
    } catch (err: any) {
      addEntry(agentId, { type: 'error', text: `[FileBrowser] Download failed: ${err.message}` });
    }
    setContextMenu(null);
  };

  const handleDelete = async (entry: FileEntry) => {
    const remotePath = joinPath(currentPath, entry.name);
    if (!confirm(`Delete ${remotePath}?`)) return;
    try {
      const task: TaskRequest = {
        agent_id: agentId,
        type: TaskType.SHELL,
        data: btoa(entry.type === 'directory' ? `rmdir /s /q "${remotePath}"` : `del /f "${remotePath}"`),
        params: { command: 'delete' },
      };
      const res = await api.sendTask(task);
      addEntry(agentId, { type: 'info', text: `[FileBrowser] Delete queued: ${remotePath} -> task ${res.task_id}` });
      // Refresh after a delay
      setTimeout(() => listDirectory(currentPath), 2000);
    } catch (err: any) {
      addEntry(agentId, { type: 'error', text: `[FileBrowser] Delete failed: ${err.message}` });
    }
    setContextMenu(null);
  };

  const handleView = async (entry: FileEntry) => {
    const remotePath = joinPath(currentPath, entry.name);
    try {
      const task: TaskRequest = {
        agent_id: agentId,
        type: TaskType.DOWNLOAD,
        data: btoa(remotePath),
        params: { path: remotePath, preview: 'true' },
      };
      const res = await api.sendTask(task);
      addEntry(agentId, { type: 'info', text: `[FileBrowser] View file queued: ${remotePath} -> task ${res.task_id}` });
    } catch (err: any) {
      addEntry(agentId, { type: 'error', text: `[FileBrowser] View failed: ${err.message}` });
    }
    setContextMenu(null);
  };

  const handleUpload = async () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = async () => {
        const base64 = (reader.result as string).split(',')[1] || '';
        const remotePath = joinPath(currentPath, file.name);
        try {
          const task: TaskRequest = {
            agent_id: agentId,
            type: TaskType.UPLOAD,
            data: base64,
            params: { path: remotePath, filename: file.name },
          };
          const res = await api.sendTask(task);
          addEntry(agentId, { type: 'info', text: `[FileBrowser] Upload queued: ${file.name} -> ${remotePath} (task ${res.task_id})` });
          setTimeout(() => listDirectory(currentPath), 3000);
        } catch (err: any) {
          addEntry(agentId, { type: 'error', text: `[FileBrowser] Upload failed: ${err.message}` });
        }
      };
      reader.readAsDataURL(file);
    };
    input.click();
  };

  const handlePathSubmit = () => {
    setShowPathEdit(false);
    if (pathInput.trim()) {
      navigateTo(pathInput.trim());
    }
  };

  // ── Render Helpers ─────────────────────────────────────────

  const columns: { key: SortField; label: string; width?: string }[] = [
    { key: 'name', label: 'Name' },
    { key: 'size', label: 'Size', width: '90px' },
    { key: 'modified', label: 'Modified', width: '160px' },
    { key: 'type', label: 'Type', width: '80px' },
  ];

  const fileIcon = (entry: FileEntry) => {
    if (entry.type === 'directory') return '\uD83D\uDCC1';
    const ext = entry.name.split('.').pop()?.toLowerCase();
    if (['exe', 'dll', 'sys', 'bat', 'cmd', 'ps1'].includes(ext || '')) return '\u2699';
    if (['txt', 'log', 'cfg', 'ini', 'conf', 'json', 'xml', 'yaml', 'yml'].includes(ext || '')) return '\uD83D\uDCC4';
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext || '')) return '\uD83D\uDCE6';
    return '\uD83D\uDCC4';
  };

  // ── Render ─────────────────────────────────────────────────

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
          onClick={() => navigateTo(parentPath(currentPath))}
          title="Go up"
        >
          ..
        </button>
        <button
          className="btn btn--small"
          onClick={() => listDirectory(currentPath)}
          title="Refresh"
        >
          Refresh
        </button>
        <button
          className="btn btn--small"
          onClick={handleUpload}
          title="Upload file"
        >
          Upload
        </button>

        {/* Breadcrumb / path bar */}
        <div style={{ flex: 1, marginLeft: '4px' }}>
          {showPathEdit ? (
            <input
              className="input"
              style={{ height: '26px', fontSize: '12px' }}
              value={pathInput}
              onChange={(e) => setPathInput(e.target.value)}
              onBlur={handlePathSubmit}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handlePathSubmit();
                if (e.key === 'Escape') setShowPathEdit(false);
              }}
              autoFocus
            />
          ) : (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '2px',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: '3px 6px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-secondary)',
              }}
              onClick={() => {
                setPathInput(currentPath);
                setShowPathEdit(true);
              }}
            >
              <span
                onClick={(e) => { e.stopPropagation(); navigateTo('/'); }}
                style={{ color: 'var(--red-primary)', cursor: 'pointer' }}
              >
                /
              </span>
              {pathSegments(currentPath).map((seg, i, arr) => (
                <span key={i}>
                  <span
                    style={{ color: i === arr.length - 1 ? 'var(--text-primary)' : 'var(--text-muted)', cursor: 'pointer' }}
                    onClick={(e) => {
                      e.stopPropagation();
                      const targetPath = '/' + arr.slice(0, i + 1).join('/');
                      navigateTo(targetPath);
                    }}
                  >
                    {seg}
                  </span>
                  {i < arr.length - 1 && <span style={{ color: 'var(--text-dim)', margin: '0 2px' }}>/</span>}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Error Banner */}
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

      {/* Loading indicator */}
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
          Loading directory...
        </div>
      )}

      {/* File Table */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="rtl-table">
          <thead>
            <tr>
              <th style={{ width: '28px' }}></th>
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
              <th style={{ width: '90px' }}>Permissions</th>
            </tr>
          </thead>
          <tbody>
            {!isLoading && sorted.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-dark)', padding: '24px' }}>
                  {error ? 'Failed to list directory' : 'Empty directory'}
                </td>
              </tr>
            ) : (
              sorted.map((entry, i) => (
                <tr
                  key={`${entry.name}-${i}`}
                  onDoubleClick={() => handleDoubleClick(entry)}
                  onContextMenu={(e) => handleContextMenu(e, entry)}
                  style={{ cursor: entry.type === 'directory' ? 'pointer' : 'default' }}
                >
                  <td style={{ textAlign: 'center', fontSize: '14px', padding: '4px' }}>
                    {fileIcon(entry)}
                  </td>
                  <td style={{
                    color: entry.type === 'directory' ? 'var(--blue)' : 'var(--text-secondary)',
                    fontWeight: entry.type === 'directory' ? 600 : 400,
                  }}>
                    {entry.name}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', textAlign: 'right' }}>
                    {entry.type === 'directory' ? '--' : formatSize(entry.size)}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                    {entry.modified || '--'}
                  </td>
                  <td style={{ textTransform: 'capitalize', fontSize: '11px' }}>
                    {entry.type}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
                    {entry.permissions || '--'}
                  </td>
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
        <span>{entries.length} items</span>
        <span>{currentPath}</span>
      </div>

      {/* Context Menu */}
      {contextMenu && (
        <div
          className="context-menu"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          {contextMenu.entry.type === 'directory' && (
            <div
              className="context-menu__item"
              onClick={() => {
                handleDoubleClick(contextMenu.entry);
                setContextMenu(null);
              }}
            >
              Open
            </div>
          )}
          {contextMenu.entry.type === 'file' && (
            <div className="context-menu__item" onClick={() => handleView(contextMenu.entry)}>
              View
            </div>
          )}
          <div className="context-menu__item" onClick={() => handleDownload(contextMenu.entry)}>
            Download
          </div>
          <div className="context-menu__separator" />
          <div className="context-menu__item context-menu__item--danger" onClick={() => handleDelete(contextMenu.entry)}>
            Delete
          </div>
          <div className="context-menu__separator" />
          <div
            className="context-menu__item"
            onClick={() => {
              navigator.clipboard.writeText(joinPath(currentPath, contextMenu.entry.name));
              setContextMenu(null);
            }}
          >
            Copy Path
          </div>
        </div>
      )}
    </div>
  );
}
