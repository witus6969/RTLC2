import { useEffect, useRef } from 'react';

export function usePolling(callback: () => void, intervalMs: number, enabled: boolean = true) {
  const savedCallback = useRef(callback);

  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  useEffect(() => {
    if (!enabled) return;

    // Initial call
    savedCallback.current();

    const id = setInterval(() => {
      // Don't poll when tab is hidden
      if (!document.hidden) {
        savedCallback.current();
      }
    }, intervalMs);

    return () => clearInterval(id);
  }, [intervalMs, enabled]);
}
