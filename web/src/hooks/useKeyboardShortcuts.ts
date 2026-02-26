import { useEffect } from 'react';
import { useUIStore } from '../store/uiStore';

export function useKeyboardShortcuts() {
    const { setActiveBottomTab } = useUIStore();

    useEffect(() => {
        const handler = (e: KeyboardEvent) => {
            const mod = e.ctrlKey || e.metaKey;
            if (!mod) {
                if (e.key === 'Escape') {
                    // Close any open modal - dispatch a global close event
                    document.dispatchEvent(new CustomEvent('rtlc2:close-modal'));
                    return;
                }
                return;
            }

            switch (e.key.toLowerCase()) {
                case 'd':
                    e.preventDefault();
                    setActiveBottomTab('dashboard');
                    break;
                case 'l':
                    e.preventDefault();
                    setActiveBottomTab('event-log');
                    break;
                case 'w':
                    e.preventDefault();
                    // Close current tab if closeable
                    {
                        const tabs = useUIStore.getState().bottomTabs;
                        const activeId = useUIStore.getState().activeBottomTabId;
                        const activeTab = tabs.find(t => t.id === activeId);
                        if (activeTab?.closeable) {
                            useUIStore.getState().closeBottomTab(activeId);
                        }
                    }
                    break;
                case 'tab':
                    e.preventDefault();
                    // Cycle tabs
                    {
                        const allTabs = useUIStore.getState().bottomTabs;
                        const currentId = useUIStore.getState().activeBottomTabId;
                        const idx = allTabs.findIndex(t => t.id === currentId);
                        const next = e.shiftKey
                            ? (idx - 1 + allTabs.length) % allTabs.length
                            : (idx + 1) % allTabs.length;
                        setActiveBottomTab(allTabs[next].id);
                    }
                    break;
            }
        };

        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
    }, [setActiveBottomTab]);
}
