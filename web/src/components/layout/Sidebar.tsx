import { useUIStore } from '../../store/uiStore';
import { useAuthStore } from '../../store/authStore';
import { useNotificationStore } from '../../store/notificationStore';

interface NavItem {
  id: string;
  icon: string;
  label: string;
  tabId?: string;
  action: () => void;
  adminOnly?: boolean;
  badgeKey?: 'unreadCredentials' | 'unreadEvents' | 'newAgents';
}

export default function Sidebar() {
  const {
    activeBottomTab,
    sidebarCollapsed,
    showPayloadGenerator,
    showBOFPanel,
    showCradleDialog,
    toggleSidebar,
    setActiveBottomTab,
    setShowPayloadGenerator,
    setShowBOFPanel,
    setShowCradleDialog,
  } = useUIStore();
  const logout = useAuthStore((s) => s.logout);
  const role = useAuthStore((s) => s.role);
  const notifications = useNotificationStore();

  const items: NavItem[] = [
    { id: 'dashboard', icon: '\u25C9', label: 'Dashboard', tabId: 'dashboard', action: () => setActiveBottomTab('dashboard') },
    { id: 'listeners', icon: '\u25CE', label: 'Listeners', tabId: 'listeners', action: () => setActiveBottomTab('listeners') },
    { id: 'payload', icon: '\u2699', label: 'Payload Gen', action: () => setShowPayloadGenerator(true) },
    { id: 'bof', icon: '\u26A1', label: 'BOF / Modules', action: () => setShowBOFPanel(true) },
    { id: 'assembly', icon: '\u2692', label: '.NET Assembly', tabId: 'assembly', action: () => setActiveBottomTab('assembly') },
    { id: 'events', icon: '\u2630', label: 'Event Log', tabId: 'event-log', action: () => setActiveBottomTab('event-log'), badgeKey: 'unreadEvents' },
    { id: 'plugins', icon: '\u229E', label: 'Plugins', tabId: 'plugins', action: () => setActiveBottomTab('plugins') },
    { id: 'artifacts', icon: '\u2B07', label: 'Artifacts', tabId: 'artifacts', action: () => setActiveBottomTab('artifacts') },
    { id: 'credentials', icon: '\u{1F511}', label: 'Credentials', tabId: 'credentials', action: () => setActiveBottomTab('credentials'), badgeKey: 'unreadCredentials' },
    { id: 'chat', icon: '\u{1F4AC}', label: 'Operator Chat', tabId: 'chat', action: () => setActiveBottomTab('chat') },
    { id: 'webhooks', icon: '\u{1F514}', label: 'Webhooks', tabId: 'webhooks', action: () => setActiveBottomTab('webhooks') },
    { id: 'autotasks', icon: '\u{2699}', label: 'Auto-Tasks', tabId: 'autotasks', action: () => setActiveBottomTab('autotasks') },
    { id: 'cradles', icon: '\u{2B07}', label: 'Cradles', action: () => setShowCradleDialog(true) },
    { id: 'hosted-files', icon: '\u{1F4C1}', label: 'Hosted Files', tabId: 'hosted-files', action: () => setActiveBottomTab('hosted-files') },
    { id: 'profiles', icon: '\u{1F9E9}', label: 'Profiles', tabId: 'profiles', action: () => setActiveBottomTab('profiles') },
    { id: 'reports', icon: '\u{1F4CA}', label: 'Reports', tabId: 'reports', action: () => setActiveBottomTab('reports') },
    { id: 'campaigns', icon: '\u{1F3AF}', label: 'Campaigns', tabId: 'campaigns', action: () => setActiveBottomTab('campaigns') },
    { id: 'operators', icon: '\u{1F464}', label: 'Operators', tabId: 'operators', action: () => setActiveBottomTab('operators'), adminOnly: true },
    { id: 'settings', icon: '\u2699', label: 'Settings', tabId: 'settings', action: () => setActiveBottomTab('settings') },
  ];

  const filteredItems = items.filter((item) => {
    if (item.adminOnly && role !== 'admin') return false;
    return true;
  });

  const isActive = (item: NavItem) => {
    if (item.id === 'payload' && showPayloadGenerator) return true;
    if (item.id === 'bof' && showBOFPanel) return true;
    if (item.id === 'cradles' && showCradleDialog) return true;
    if (item.tabId && activeBottomTab === item.tabId) return true;
    return false;
  };

  const getBadgeCount = (item: NavItem): number => {
    if (!item.badgeKey) return 0;
    return notifications[item.badgeKey] || 0;
  };

  const collapsed = sidebarCollapsed;
  const sidebarWidth = collapsed ? '52px' : '180px';

  return (
    <div style={{
      width: sidebarWidth,
      minWidth: sidebarWidth,
      background: '#0d0d0d',
      borderRight: '1px solid #1a1a1a',
      display: 'flex',
      flexDirection: 'column',
      paddingTop: '8px',
      gap: '2px',
      flexShrink: 0,
      transition: 'width 0.2s ease, min-width 0.2s ease',
      overflow: 'hidden',
    }}>
      {/* Header: Logo + Toggle */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: collapsed ? 'center' : 'space-between',
        padding: collapsed ? '4px 0' : '4px 10px 4px 6px',
        marginBottom: '8px',
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          cursor: 'pointer',
        }} onClick={toggleSidebar}>
          <div style={{
            width: '36px',
            height: '36px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#cc0000',
            fontWeight: 900,
            fontSize: '16px',
            fontFamily: 'var(--font-mono)',
            border: '2px solid #cc0000',
            borderRadius: '8px',
            flexShrink: 0,
          }}>
            R2
          </div>
          {!collapsed && (
            <span style={{
              color: '#cc0000',
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              fontSize: '13px',
              whiteSpace: 'nowrap',
            }}>
              RTLC2
            </span>
          )}
        </div>
        {!collapsed && (
          <button
            onClick={toggleSidebar}
            title="Collapse sidebar"
            style={{
              background: 'transparent',
              border: 'none',
              color: '#555',
              cursor: 'pointer',
              fontSize: '14px',
              padding: '4px',
              display: 'flex',
              alignItems: 'center',
            }}
          >
            {'\u276E'}
          </button>
        )}
      </div>

      {/* Nav Items */}
      <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden' }}>
        {filteredItems.map((item) => {
          const active = isActive(item);
          const badge = getBadgeCount(item);
          return (
            <button
              key={item.id}
              onClick={item.action}
              title={collapsed ? item.label : undefined}
              style={{
                width: '100%',
                height: '38px',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: collapsed ? '0' : '0 12px',
                justifyContent: collapsed ? 'center' : 'flex-start',
                background: active ? '#1a0000' : 'transparent',
                border: 'none',
                borderLeft: active ? '3px solid #cc0000' : '3px solid transparent',
                cursor: 'pointer',
                color: active ? '#cc0000' : '#808080',
                fontSize: collapsed ? '18px' : '16px',
                transition: 'all 0.15s',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                position: 'relative',
              }}
              onMouseEnter={(e) => {
                if (!active) {
                  e.currentTarget.style.background = '#1a0000';
                  e.currentTarget.style.color = '#cc0000';
                }
              }}
              onMouseLeave={(e) => {
                if (!active) {
                  e.currentTarget.style.background = 'transparent';
                  e.currentTarget.style.color = '#808080';
                }
              }}
            >
              <span style={{ flexShrink: 0, width: '24px', textAlign: 'center', position: 'relative' }}>
                {item.icon}
                {badge > 0 && (
                  <span style={{
                    position: 'absolute',
                    top: '-4px',
                    right: '-4px',
                    width: '14px',
                    height: '14px',
                    borderRadius: '50%',
                    background: '#cc0000',
                    color: '#fff',
                    fontSize: '8px',
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    lineHeight: 1,
                  }}>
                    {badge > 9 ? '9+' : badge}
                  </span>
                )}
              </span>
              {!collapsed && (
                <span style={{
                  fontSize: '12px',
                  fontWeight: active ? 700 : 500,
                  letterSpacing: '0.3px',
                }}>
                  {item.label}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Expand button when collapsed */}
      {collapsed && (
        <button
          onClick={toggleSidebar}
          title="Expand sidebar"
          style={{
            width: '100%',
            height: '38px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            color: '#555',
            fontSize: '14px',
            transition: 'all 0.15s',
          }}
          onMouseEnter={(e) => { e.currentTarget.style.color = '#cc0000'; }}
          onMouseLeave={(e) => { e.currentTarget.style.color = '#555'; }}
        >
          {'\u276F'}
        </button>
      )}

      {/* Logout */}
      <button
        onClick={logout}
        title="Logout"
        style={{
          width: '100%',
          height: '38px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: collapsed ? '0' : '0 12px',
          justifyContent: collapsed ? 'center' : 'flex-start',
          background: 'transparent',
          border: 'none',
          borderLeft: '3px solid transparent',
          cursor: 'pointer',
          color: '#555',
          fontSize: collapsed ? '16px' : '14px',
          marginBottom: '8px',
          transition: 'all 0.15s',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.background = '#1a0000';
          e.currentTarget.style.color = '#cc0000';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = 'transparent';
          e.currentTarget.style.color = '#555';
        }}
      >
        <span style={{ flexShrink: 0, width: '24px', textAlign: 'center' }}>{'\u23FB'}</span>
        {!collapsed && <span style={{ fontSize: '12px', fontWeight: 500 }}>Logout</span>}
      </button>
    </div>
  );
}
