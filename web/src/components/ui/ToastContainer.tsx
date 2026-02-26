import { useToastStore, type Toast } from '../../store/toastStore';

const iconMap: Record<Toast['type'], string> = {
  success: '\u2713',
  error: '\u2717',
  warning: '\u26A0',
  info: '\u2139',
};

const colorMap: Record<Toast['type'], string> = {
  success: '#00cc00',
  error: '#cc0000',
  warning: '#cc8800',
  info: '#0088cc',
};

export default function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts);
  const removeToast = useToastStore((s) => s.removeToast);

  if (toasts.length === 0) return null;

  return (
    <div style={{
      position: 'fixed', bottom: 16, right: 16, zIndex: 9999,
      display: 'flex', flexDirection: 'column-reverse', gap: 8,
      pointerEvents: 'none', maxWidth: 380,
    }}>
      {toasts.map((toast) => {
        const elapsed = Date.now() - toast.createdAt;
        const progress = Math.max(0, 1 - elapsed / toast.duration);
        return (
          <div key={toast.id} style={{
            pointerEvents: 'auto',
            background: '#1a1a1a', borderRadius: 6,
            borderLeft: `4px solid ${colorMap[toast.type]}`,
            boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
            padding: '10px 14px', minWidth: 300,
            animation: 'slideIn 0.3s ease-out',
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
              <span style={{
                color: colorMap[toast.type], fontSize: 16, fontWeight: 'bold',
                lineHeight: '20px', flexShrink: 0,
              }}>
                {iconMap[toast.type]}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ color: '#e0e0e0', fontSize: 13, fontWeight: 600 }}>
                  {toast.title}
                </div>
                {toast.message && (
                  <div style={{ color: '#999', fontSize: 12, marginTop: 2, wordBreak: 'break-word' }}>
                    {toast.message}
                  </div>
                )}
              </div>
              <button
                onClick={() => removeToast(toast.id)}
                style={{
                  background: 'none', border: 'none', color: '#666',
                  cursor: 'pointer', fontSize: 14, padding: '0 2px',
                  lineHeight: '20px', flexShrink: 0,
                }}
              >
                \u2715
              </button>
            </div>
            <div style={{
              height: 2, background: '#222', borderRadius: 1,
              marginTop: 8, overflow: 'hidden',
            }}>
              <div style={{
                height: '100%', background: colorMap[toast.type],
                width: `${progress * 100}%`, transition: 'width 1s linear',
              }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
