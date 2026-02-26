// ═══════════════════════════════════════════════════════════════
//  RTLC2 Operator Chat Panel
//  Real-time operator communication with auto-scroll,
//  timestamp display, and per-operator color coding.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useRef, useCallback } from 'react';
import { useChatStore } from '../../store/chatStore';
import { useAuthStore } from '../../store/authStore';
import type { ChatMessage } from '../../types';

// ── Operator color assignment ────────────────────────────────
// Deterministic color from operator name using a hash

const OPERATOR_COLORS = [
  '#cc0000', // red
  '#00cc00', // green
  '#4488cc', // blue
  '#ff6600', // orange
  '#00cccc', // cyan
  '#cc00cc', // magenta
  '#cccc00', // yellow
  '#ff3399', // pink
  '#33cc66', // sea green
  '#9966ff', // purple
  '#ff9933', // amber
  '#66ccff', // sky blue
];

function getOperatorColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) - hash + name.charCodeAt(i)) | 0;
  }
  return OPERATOR_COLORS[Math.abs(hash) % OPERATOR_COLORS.length];
}

// ── Format timestamp ─────────────────────────────────────────

function formatTime(ts: string): string {
  try {
    const date = new Date(ts);
    return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

function formatDate(ts: string): string {
  try {
    const date = new Date(ts);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  } catch {
    return '';
  }
}

// Check if two timestamps are on different days
function isDifferentDay(ts1: string, ts2: string): boolean {
  try {
    const d1 = new Date(ts1).toDateString();
    const d2 = new Date(ts2).toDateString();
    return d1 !== d2;
  } catch {
    return false;
  }
}

// ── Component ────────────────────────────────────────────────

export default function ChatPanel() {
  const { messages, connected, isLoading, error, fetchHistory, sendMessage, clearError } = useChatStore();
  const currentUser = useAuthStore((s) => s.username);

  const [inputText, setInputText] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Fetch history on mount
  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (autoScroll && messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, autoScroll]);

  // Detect if user has scrolled up (disable auto-scroll)
  const handleScroll = useCallback(() => {
    const container = messagesContainerRef.current;
    if (!container) return;
    const isAtBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 40;
    setAutoScroll(isAtBottom);
  }, []);

  // Send message
  const handleSend = useCallback(async () => {
    const text = inputText.trim();
    if (!text) return;
    setInputText('');
    await sendMessage(text);
  }, [inputText, sendMessage]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // ── Render message ─────────────────────────────────────────

  const renderMessage = (msg: ChatMessage, index: number) => {
    const isOwnMessage = msg.operator === currentUser;
    const color = getOperatorColor(msg.operator);
    const prevMsg = index > 0 ? messages[index - 1] : null;
    const showDaySeparator = !prevMsg || isDifferentDay(prevMsg.timestamp, msg.timestamp);
    // Group consecutive messages from the same operator
    const showAuthor = !prevMsg || prevMsg.operator !== msg.operator || showDaySeparator;

    return (
      <div key={msg.id}>
        {/* Day separator */}
        {showDaySeparator && (
          <div style={{
            textAlign: 'center',
            padding: '8px 0',
            margin: '4px 0',
          }}>
            <span style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-primary)',
              borderRadius: 'var(--radius-sm)',
              padding: '2px 12px',
              fontSize: '10px',
              color: 'var(--text-dim)',
              fontWeight: 600,
              textTransform: 'uppercase',
            }}>
              {formatDate(msg.timestamp)}
            </span>
          </div>
        )}

        <div style={{
          padding: showAuthor ? '6px 14px 2px' : '1px 14px',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '8px',
        }}>
          {/* Timestamp */}
          <span style={{
            fontSize: '10px',
            color: 'var(--text-dim)',
            fontFamily: 'var(--font-mono)',
            flexShrink: 0,
            width: '58px',
            marginTop: showAuthor ? '2px' : '0',
            visibility: showAuthor ? 'visible' : 'hidden',
          }}>
            {formatTime(msg.timestamp)}
          </span>

          {/* Message content */}
          <div style={{ flex: 1, minWidth: 0 }}>
            {showAuthor && (
              <span style={{
                color,
                fontWeight: 700,
                fontSize: '12px',
                marginRight: '8px',
              }}>
                {msg.operator}
                {isOwnMessage && (
                  <span style={{ color: 'var(--text-dim)', fontWeight: 400, fontSize: '10px', marginLeft: '4px' }}>
                    (you)
                  </span>
                )}
              </span>
            )}
            <div style={{
              color: 'var(--text-secondary)',
              fontSize: '12px',
              lineHeight: '1.5',
              wordBreak: 'break-word',
              whiteSpace: 'pre-wrap',
            }}>
              {msg.text}
            </div>
          </div>
        </div>
      </div>
    );
  };

  // ── Main Render ────────────────────────────────────────────

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg-secondary)' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '6px 10px',
        borderBottom: '1px solid var(--border-primary)',
        background: 'var(--bg-tertiary)',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            fontWeight: 700,
            fontSize: '12px',
            color: 'var(--red-primary)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
          }}>
            Operator Chat
          </span>
          <span style={{
            display: 'inline-block',
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: connected ? 'var(--green)' : 'var(--red-primary)',
            boxShadow: connected ? '0 0 6px var(--green)' : '0 0 6px var(--red-primary)',
          }} />
          <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
          {messages.length} messages
        </span>
      </div>

      {/* Error banner */}
      {error && (
        <div style={{
          padding: '6px 10px',
          background: 'var(--red-bg)',
          borderBottom: '1px solid var(--red-dark)',
          color: 'var(--red-light)',
          fontSize: '11px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexShrink: 0,
        }}>
          <span>{error}</span>
          <button
            className="btn btn--small"
            style={{ padding: '1px 6px', fontSize: '10px' }}
            onClick={clearError}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Loading indicator */}
      {isLoading && messages.length === 0 && (
        <div style={{
          padding: '12px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '8px',
          color: 'var(--text-dim)',
          fontSize: '11px',
        }}>
          <div className="spinner" style={{ width: '14px', height: '14px', borderWidth: '1.5px' }} />
          Loading chat history...
        </div>
      )}

      {/* Messages */}
      <div
        ref={messagesContainerRef}
        onScroll={handleScroll}
        style={{
          flex: 1,
          overflow: 'auto',
          padding: '4px 0',
        }}
      >
        {messages.length === 0 && !isLoading && (
          <div style={{
            textAlign: 'center',
            padding: '40px 20px',
            color: 'var(--text-dark)',
            fontSize: '12px',
          }}>
            No messages yet. Start the conversation.
          </div>
        )}

        {messages.map((msg, i) => renderMessage(msg, i))}

        <div ref={messagesEndRef} />
      </div>

      {/* Scroll-to-bottom indicator */}
      {!autoScroll && (
        <div style={{
          position: 'relative',
        }}>
          <button
            onClick={() => {
              setAutoScroll(true);
              messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
            }}
            style={{
              position: 'absolute',
              bottom: '4px',
              right: '16px',
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border-secondary)',
              borderRadius: 'var(--radius-md)',
              color: 'var(--text-muted)',
              fontSize: '10px',
              padding: '4px 10px',
              cursor: 'pointer',
              zIndex: 10,
            }}
          >
            Scroll to bottom
          </button>
        </div>
      )}

      {/* Input area */}
      <div style={{
        padding: '8px 10px',
        borderTop: '1px solid var(--border-primary)',
        background: 'var(--bg-tertiary)',
        flexShrink: 0,
        display: 'flex',
        gap: '8px',
        alignItems: 'flex-end',
      }}>
        <div style={{ flex: 1 }}>
          <textarea
            className="input"
            style={{
              resize: 'none',
              minHeight: '32px',
              maxHeight: '100px',
              fontSize: '12px',
              lineHeight: '1.4',
              padding: '6px 10px',
            }}
            rows={1}
            placeholder={connected ? 'Type a message...' : 'Disconnected - messages may not be delivered'}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={handleKeyDown}
          />
        </div>
        <button
          className="btn btn--primary btn--small"
          onClick={handleSend}
          disabled={!inputText.trim()}
          style={{ height: '32px' }}
        >
          Send
        </button>
      </div>
    </div>
  );
}
