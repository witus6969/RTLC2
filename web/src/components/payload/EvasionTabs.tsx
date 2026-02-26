import { useState } from 'react';
import { EVASION_CATEGORIES } from './payloadData';

interface Props {
  os: string;
  evasionState: Record<string, Record<string, boolean>>;
  onToggle: (category: string, field: string, value: boolean) => void;
}

export default function EvasionTabs({ os, evasionState, onToggle }: Props) {
  const [activeTab, setActiveTab] = useState(0);
  const isWindows = os === 'windows';

  // If current tab is disabled, switch to first enabled
  const currentCat = EVASION_CATEGORIES[activeTab];
  if (currentCat?.windowsOnly && !isWindows) {
    const firstEnabled = EVASION_CATEGORIES.findIndex((c) => !c.windowsOnly);
    if (firstEnabled >= 0 && firstEnabled !== activeTab) {
      setActiveTab(firstEnabled);
    }
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Tab bar */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        background: '#0d0d0d',
        borderBottom: '1px solid #1a1a1a',
        gap: '1px',
      }}>
        {EVASION_CATEGORIES.map((cat, i) => {
          const disabled = cat.windowsOnly && !isWindows;
          const active = activeTab === i;
          return (
            <button
              key={cat.key}
              onClick={() => !disabled && setActiveTab(i)}
              disabled={disabled}
              style={{
                padding: '6px 10px',
                background: active ? '#0d0d0d' : '#1a1a1a',
                border: 'none',
                borderBottom: active ? '2px solid #cc0000' : '2px solid transparent',
                color: disabled ? '#333' : active ? '#cc0000' : '#888',
                fontSize: '10px',
                fontWeight: active ? 700 : 400,
                cursor: disabled ? 'not-allowed' : 'pointer',
                opacity: disabled ? 0.3 : 1,
                transition: 'all 0.15s',
              }}
            >
              {cat.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px' }}>
        {EVASION_CATEGORIES[activeTab] && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {EVASION_CATEGORIES[activeTab].techniques.map((tech) => {
              const catKey = EVASION_CATEGORIES[activeTab].key;
              const checked = evasionState[catKey]?.[tech.field] ?? tech.defaultOn;
              const disabled = EVASION_CATEGORIES[activeTab].windowsOnly && !isWindows;

              return (
                <label
                  key={tech.field}
                  className={`checkbox-wrapper ${disabled ? 'disabled' : ''}`}
                >
                  <input
                    type="checkbox"
                    checked={disabled ? false : checked}
                    disabled={disabled}
                    onChange={(e) => onToggle(catKey, tech.field, e.target.checked)}
                  />
                  {tech.name}
                </label>
              );
            })}
          </div>
        )}
      </div>

      {/* Counter */}
      <div style={{
        padding: '6px 12px',
        borderTop: '1px solid #1a1a1a',
        fontSize: '10px',
        color: '#666',
        textAlign: 'right',
      }}>
        {(() => {
          let total = 0;
          for (const cat of EVASION_CATEGORIES) {
            if (cat.windowsOnly && !isWindows) continue;
            for (const tech of cat.techniques) {
              if (evasionState[cat.key]?.[tech.field] ?? tech.defaultOn) total++;
            }
          }
          const max = isWindows ? 100 : EVASION_CATEGORIES.filter(c => !c.windowsOnly).length * 10;
          return `${total}/${max} techniques enabled`;
        })()}
      </div>
    </div>
  );
}
