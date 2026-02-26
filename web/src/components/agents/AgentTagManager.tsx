// ═══════════════════════════════════════════════════════════════
//  RTLC2 Agent Tag Manager
//  Inline tag editor with color-coded badges, add/remove tags.
// ═══════════════════════════════════════════════════════════════

import { useState, useRef, useEffect } from 'react';
import { api } from '../../api/client';

interface AgentTagManagerProps {
  agentId: string;
  currentTags: string[];
}

// Predefined palette for tag colors (cycles through)
const TAG_COLORS = [
  { bg: '#cc000033', border: '#cc000066', text: '#ff4444' },
  { bg: '#0066cc33', border: '#0066cc66', text: '#4499ff' },
  { bg: '#00994433', border: '#00994466', text: '#33cc77' },
  { bg: '#cc660033', border: '#cc660066', text: '#ffaa33' },
  { bg: '#9933cc33', border: '#9933cc66', text: '#cc77ff' },
  { bg: '#00999933', border: '#00999966', text: '#33cccc' },
  { bg: '#cc339933', border: '#cc339966', text: '#ff66bb' },
  { bg: '#66993333', border: '#66993366', text: '#99cc55' },
];

function getTagColor(index: number) {
  return TAG_COLORS[index % TAG_COLORS.length];
}

export default function AgentTagManager({ agentId, currentTags }: AgentTagManagerProps) {
  const [tags, setTags] = useState<string[]>(currentTags);
  const [showInput, setShowInput] = useState(false);
  const [newTag, setNewTag] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Sync with prop changes
  useEffect(() => {
    setTags(currentTags);
  }, [currentTags]);

  // Focus input when shown
  useEffect(() => {
    if (showInput && inputRef.current) {
      inputRef.current.focus();
    }
  }, [showInput]);

  const saveTags = async (updatedTags: string[]) => {
    setIsSaving(true);
    setError(null);
    try {
      await api.updateAgentTags(agentId, updatedTags);
      setTags(updatedTags);
    } catch (err: any) {
      setError(err.message || 'Failed to update tags');
      // Revert
      setTags(tags);
    } finally {
      setIsSaving(false);
    }
  };

  const handleAddTag = () => {
    const trimmed = newTag.trim().toLowerCase();
    if (!trimmed) {
      setShowInput(false);
      return;
    }
    if (tags.includes(trimmed)) {
      setError('Tag already exists');
      setNewTag('');
      return;
    }
    const updated = [...tags, trimmed];
    saveTags(updated);
    setNewTag('');
    setShowInput(false);
  };

  const handleRemoveTag = (tag: string) => {
    const updated = tags.filter((t) => t !== tag);
    saveTags(updated);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleAddTag();
    } else if (e.key === 'Escape') {
      setShowInput(false);
      setNewTag('');
    }
  };

  // ── Styles ──────────────────────────────────────────────────

  const containerStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: '4px',
    padding: '4px 0',
  };

  const badgeStyle = (idx: number): React.CSSProperties => {
    const color = getTagColor(idx);
    return {
      display: 'inline-flex',
      alignItems: 'center',
      gap: '4px',
      padding: '2px 8px',
      background: color.bg,
      border: `1px solid ${color.border}`,
      borderRadius: '12px',
      fontSize: '11px',
      fontFamily: '"Cascadia Code", "Fira Code", "Consolas", monospace',
      color: color.text,
      lineHeight: '18px',
      whiteSpace: 'nowrap',
    };
  };

  const removeBtnStyle: React.CSSProperties = {
    background: 'none',
    border: 'none',
    color: 'inherit',
    cursor: 'pointer',
    fontSize: '13px',
    padding: '0',
    lineHeight: 1,
    opacity: 0.6,
    fontFamily: 'monospace',
  };

  const addBtnStyle: React.CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '22px',
    height: '22px',
    background: '#1a1a1a',
    border: '1px solid #333',
    borderRadius: '50%',
    color: '#cc0000',
    cursor: 'pointer',
    fontSize: '14px',
    fontFamily: 'monospace',
    lineHeight: 1,
    padding: 0,
  };

  const inputStyle: React.CSSProperties = {
    padding: '2px 8px',
    background: '#0a0a0a',
    border: '1px solid #cc0000',
    borderRadius: '12px',
    color: '#e0e0e0',
    fontSize: '11px',
    fontFamily: '"Cascadia Code", "Fira Code", "Consolas", monospace',
    outline: 'none',
    width: '120px',
    height: '22px',
  };

  // ── Render ──────────────────────────────────────────────────

  return (
    <div style={containerStyle}>
      {tags.map((tag, idx) => (
        <span key={tag} style={badgeStyle(idx)}>
          {tag}
          <button
            style={removeBtnStyle}
            onClick={() => handleRemoveTag(tag)}
            disabled={isSaving}
            title={`Remove tag "${tag}"`}
            onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.opacity = '1'; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.opacity = '0.6'; }}
          >
            x
          </button>
        </span>
      ))}

      {showInput ? (
        <input
          ref={inputRef}
          type="text"
          placeholder="tag name..."
          value={newTag}
          onChange={(e) => setNewTag(e.target.value)}
          onKeyDown={handleKeyDown}
          onBlur={handleAddTag}
          style={inputStyle}
          maxLength={30}
        />
      ) : (
        <button
          style={addBtnStyle}
          onClick={() => setShowInput(true)}
          disabled={isSaving}
          title="Add tag"
          onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = '#cc0000'; }}
          onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = '#333'; }}
        >
          +
        </button>
      )}

      {isSaving && (
        <span style={{ fontSize: '10px', color: '#555', marginLeft: '4px' }}>
          saving...
        </span>
      )}

      {error && (
        <span style={{ fontSize: '10px', color: '#cc0000', marginLeft: '4px' }}>
          {error}
        </span>
      )}
    </div>
  );
}
