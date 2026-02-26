// ═══════════════════════════════════════════════════════════════
//  RTLC2 Screenshot Viewer
//  Gallery view of captured screenshots from agent task results.
//  Displays thumbnails in a grid, click-to-expand full resolution.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../../api/client';
import type { TaskResult } from '../../types';
import { TaskType, TaskStatus } from '../../types';

interface ScreenshotViewerProps {
  agentId: string;
}

interface ScreenshotEntry {
  taskId: string;
  timestamp: string;
  blobUrl: string;
}

export default function ScreenshotViewer({ agentId }: ScreenshotViewerProps) {
  const [screenshots, setScreenshots] = useState<ScreenshotEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const blobUrlsRef = useRef<string[]>([]);

  // Cleanup blob URLs on unmount
  useEffect(() => {
    return () => {
      blobUrlsRef.current.forEach((url) => URL.revokeObjectURL(url));
    };
  }, []);

  const fetchScreenshots = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const res = await api.getAgentTasks(agentId);
      const tasks = (res.tasks || []).filter(
        (t) => t.type === TaskType.SCREENSHOT
      );

      const entries: ScreenshotEntry[] = [];

      for (const task of tasks) {
        try {
          const result: TaskResult = await api.getTaskResult(task.task_id);
          if (result.status !== TaskStatus.COMPLETE || !result.output) continue;

          // Decode base64 output to image blob
          const raw = atob(result.output);
          const bytes = new Uint8Array(raw.length);
          for (let i = 0; i < raw.length; i++) {
            bytes[i] = raw.charCodeAt(i);
          }

          // Detect image type from magic bytes
          let mimeType = 'image/png';
          if (bytes[0] === 0xff && bytes[1] === 0xd8) {
            mimeType = 'image/jpeg';
          } else if (
            bytes[0] === 0x42 &&
            bytes[1] === 0x4d
          ) {
            mimeType = 'image/bmp';
          }

          const blob = new Blob([bytes], { type: mimeType });
          const blobUrl = URL.createObjectURL(blob);
          blobUrlsRef.current.push(blobUrl);

          entries.push({
            taskId: task.task_id,
            timestamp: result.updated_at || result.created_at,
            blobUrl,
          });
        } catch {
          // Skip tasks that fail to load
        }
      }

      // Sort newest first
      entries.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      setScreenshots(entries);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch screenshots');
    } finally {
      setIsLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    fetchScreenshots();
  }, [fetchScreenshots]);

  const handleDownload = (entry: ScreenshotEntry) => {
    const link = document.createElement('a');
    link.href = entry.blobUrl;
    link.download = `screenshot_${agentId.slice(0, 8)}_${entry.timestamp.replace(/[:\s]/g, '_')}.png`;
    link.click();
  };

  const formatTimestamp = (ts: string): string => {
    try {
      const d = new Date(ts);
      return d.toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      });
    } catch {
      return ts;
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

  const gridStyle: React.CSSProperties = {
    flex: 1,
    overflow: 'auto',
    padding: '12px',
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))',
    gap: '12px',
    alignContent: 'start',
  };

  const thumbContainerStyle: React.CSSProperties = {
    position: 'relative',
    width: '100%',
    height: '150px',
    background: '#111',
    border: '1px solid #222',
    borderRadius: '4px',
    overflow: 'hidden',
    cursor: 'pointer',
    transition: 'border-color 0.15s',
  };

  const thumbImgStyle: React.CSSProperties = {
    width: '100%',
    height: '100%',
    objectFit: 'cover',
  };

  const thumbOverlayStyle: React.CSSProperties = {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    padding: '4px 6px',
    background: 'linear-gradient(transparent, rgba(0,0,0,0.85))',
    fontSize: '10px',
    fontFamily: 'monospace',
    color: '#aaa',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  };

  const overlayBackdropStyle: React.CSSProperties = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0,0,0,0.9)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
  };

  const overlayImgStyle: React.CSSProperties = {
    maxWidth: '90vw',
    maxHeight: '80vh',
    objectFit: 'contain',
    border: '1px solid #333',
    borderRadius: '4px',
  };

  const overlayBarStyle: React.CSSProperties = {
    display: 'flex',
    gap: '12px',
    alignItems: 'center',
    marginTop: '12px',
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
          Screenshots
        </span>
        <span style={{ fontSize: '11px', color: '#555' }}>
          ({screenshots.length} captured)
        </span>
        <div style={{ flex: 1 }} />
        <button
          style={btnAccentStyle}
          onClick={fetchScreenshots}
          disabled={isLoading}
        >
          {isLoading ? 'Loading...' : 'Refresh'}
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

      {/* Gallery Grid */}
      {screenshots.length === 0 && !isLoading ? (
        <div style={emptyStyle}>
          <span style={{ fontSize: '32px', opacity: 0.3 }}>[ ]</span>
          <span>No screenshots captured yet</span>
          <span style={{ fontSize: '11px', color: '#333' }}>
            Use the "screenshot" command to capture the agent's screen
          </span>
        </div>
      ) : (
        <div style={gridStyle}>
          {screenshots.map((entry, idx) => (
            <div
              key={entry.taskId}
              style={thumbContainerStyle}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLDivElement).style.borderColor = '#cc0000';
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLDivElement).style.borderColor = '#222';
              }}
              onClick={() => setExpandedIndex(idx)}
            >
              <img
                src={entry.blobUrl}
                alt={`Screenshot ${idx + 1}`}
                style={thumbImgStyle}
              />
              <div style={thumbOverlayStyle}>
                <span>{formatTimestamp(entry.timestamp)}</span>
                <button
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#cc0000',
                    cursor: 'pointer',
                    fontSize: '12px',
                    padding: '2px',
                    fontFamily: 'monospace',
                  }}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleDownload(entry);
                  }}
                  title="Download"
                >
                  [DL]
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Full-Resolution Overlay */}
      {expandedIndex !== null && screenshots[expandedIndex] && (
        <div
          style={overlayBackdropStyle}
          onClick={() => setExpandedIndex(null)}
        >
          <img
            src={screenshots[expandedIndex].blobUrl}
            alt="Full resolution screenshot"
            style={overlayImgStyle}
            onClick={(e) => e.stopPropagation()}
          />
          <div style={overlayBarStyle}>
            <span style={{ fontSize: '12px', color: '#888', fontFamily: 'monospace' }}>
              {formatTimestamp(screenshots[expandedIndex].timestamp)}
            </span>
            <button
              style={btnAccentStyle}
              onClick={(e) => {
                e.stopPropagation();
                handleDownload(screenshots[expandedIndex!]);
              }}
            >
              Download
            </button>
            <button
              style={btnStyle}
              onClick={(e) => {
                e.stopPropagation();
                if (expandedIndex > 0) setExpandedIndex(expandedIndex - 1);
              }}
              disabled={expandedIndex === 0}
            >
              Prev
            </button>
            <span style={{ fontSize: '11px', color: '#555' }}>
              {expandedIndex + 1} / {screenshots.length}
            </span>
            <button
              style={btnStyle}
              onClick={(e) => {
                e.stopPropagation();
                if (expandedIndex < screenshots.length - 1) setExpandedIndex(expandedIndex + 1);
              }}
              disabled={expandedIndex === screenshots.length - 1}
            >
              Next
            </button>
            <button
              style={{ ...btnStyle, color: '#cc0000' }}
              onClick={() => setExpandedIndex(null)}
            >
              Close [X]
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
