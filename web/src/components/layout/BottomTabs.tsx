import { lazy, Suspense } from 'react';
import { useUIStore } from '../../store/uiStore';
import Dashboard from '../dashboard/Dashboard';
import ListenerPanel from '../listeners/ListenerPanel';
import EventLog from '../events/EventLog';
import TaskPanel from '../tasks/TaskPanel';
import PluginPanel from '../plugins/PluginPanel';
import ArtifactsPanel from '../artifacts/ArtifactsPanel';
import CredentialPanel from '../credentials/CredentialPanel';
import ChatPanel from '../chat/ChatPanel';

// Lazy-loaded panels for new features
const WebhookPanel = lazy(() => import('../webhooks/WebhookPanel'));
const AutoTaskPanel = lazy(() => import('../autotasks/AutoTaskPanel'));
const ScreenshotViewer = lazy(() => import('../agents/ScreenshotViewer'));
const KeyloggerViewer = lazy(() => import('../agents/KeyloggerViewer'));
const SocksManager = lazy(() => import('../agents/SocksManager'));
const TokenManager = lazy(() => import('../agents/TokenManager'));
const ReportPanel = lazy(() => import('../reports/ReportPanel'));
const CampaignPanel = lazy(() => import('../campaigns/CampaignPanel'));
const OperatorPanel = lazy(() => import('../operators/OperatorPanel'));
const HostedFilesPanel = lazy(() => import('../hosted/HostedFilesPanel'));
const MalleableProfilePanel = lazy(() => import('../profiles/MalleableProfilePanel'));
const AssemblyPanel = lazy(() => import('../assembly/AssemblyPanel'));
const SettingsPanel = lazy(() => import('../settings/SettingsPanel'));

function LazyWrap({ children }: { children: React.ReactNode }) {
  return (
    <Suspense fallback={<div style={{ color: '#555', padding: 20, textAlign: 'center' }}>Loading...</div>}>
      {children}
    </Suspense>
  );
}

export default function BottomTabs() {
  const { bottomTabs, activeBottomTab, setActiveBottomTab, closeBottomTab } = useUIStore();

  const renderContent = () => {
    const tab = bottomTabs.find((t) => t.id === activeBottomTab);
    if (!tab) return null;

    switch (tab.type) {
      case 'dashboard':
        return <Dashboard />;
      case 'listeners':
        return <ListenerPanel />;
      case 'event-log':
        return <EventLog />;
      case 'plugins':
        return <PluginPanel />;
      case 'artifacts':
        return <ArtifactsPanel />;
      case 'credentials':
        return <CredentialPanel />;
      case 'chat':
        return <ChatPanel />;
      case 'agent':
        return tab.agentId ? <TaskPanel agentId={tab.agentId} /> : null;
      case 'webhooks':
        return <LazyWrap><WebhookPanel /></LazyWrap>;
      case 'autotasks':
        return <LazyWrap><AutoTaskPanel /></LazyWrap>;
      case 'screenshot':
        return tab.agentId ? <LazyWrap><ScreenshotViewer agentId={tab.agentId} /></LazyWrap> : null;
      case 'keylogger':
        return tab.agentId ? <LazyWrap><KeyloggerViewer agentId={tab.agentId} /></LazyWrap> : null;
      case 'socks':
        return tab.agentId ? <LazyWrap><SocksManager agentId={tab.agentId} /></LazyWrap> : null;
      case 'tokens':
        return tab.agentId ? <LazyWrap><TokenManager agentId={tab.agentId} /></LazyWrap> : null;
      case 'reports':
        return <LazyWrap><ReportPanel /></LazyWrap>;
      case 'campaigns':
        return <LazyWrap><CampaignPanel /></LazyWrap>;
      case 'operators':
        return <LazyWrap><OperatorPanel /></LazyWrap>;
      case 'hosted-files':
        return <LazyWrap><HostedFilesPanel /></LazyWrap>;
      case 'profiles':
        return <LazyWrap><MalleableProfilePanel /></LazyWrap>;
      case 'assembly':
        return <LazyWrap><AssemblyPanel /></LazyWrap>;
      case 'settings':
        return <LazyWrap><SettingsPanel /></LazyWrap>;
      default:
        return null;
    }
  };

  return (
    <div className="tabs" style={{ height: '100%' }}>
      <div className="tabs__bar">
        {bottomTabs.map((tab) => (
          <div
            key={tab.id}
            className={`tabs__tab ${activeBottomTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveBottomTab(tab.id)}
          >
            <span>{tab.label}</span>
            {tab.closeable && (
              <button
                className="tabs__close"
                onClick={(e) => {
                  e.stopPropagation();
                  closeBottomTab(tab.id);
                }}
              >
                x
              </button>
            )}
          </div>
        ))}
      </div>
      <div className="tabs__content">
        {renderContent()}
      </div>
    </div>
  );
}
