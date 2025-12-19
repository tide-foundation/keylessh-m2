import { useCallback, useEffect, useMemo, useRef, useState } from "react";

export function useAutoRefresh(options: {
  intervalSeconds: number;
  enabled?: boolean;
  refresh: () => void | Promise<unknown>;
  blockWhile?: boolean;
  isBlocked?: boolean;
}) {
  const { intervalSeconds, enabled = true, refresh, blockWhile = true, isBlocked = false } = options;

  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;

  const isBlockedRef = useRef(isBlocked);
  useEffect(() => {
    isBlockedRef.current = isBlocked;
  }, [isBlocked]);

  const [nextRefreshAt, setNextRefreshAt] = useState(() => Date.now() + intervalSeconds * 1000);
  const [now, setNow] = useState(() => Date.now());

  const secondsRemaining = useMemo(() => {
    if (!enabled) return null;
    return Math.max(0, Math.ceil((nextRefreshAt - now) / 1000));
  }, [enabled, nextRefreshAt, now]);

  useEffect(() => {
    if (!enabled) return;
    const id = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(id);
  }, [enabled]);

  const runRefresh = useCallback(async () => {
    if (!enabled) return;
    if (blockWhile && isBlockedRef.current) return;
    await refreshRef.current();
    setNextRefreshAt(Date.now() + intervalSeconds * 1000);
  }, [enabled, blockWhile, intervalSeconds]);

  useEffect(() => {
    if (!enabled) return;
    if (blockWhile && isBlockedRef.current) return;
    if (now < nextRefreshAt) return;
    void runRefresh();
  }, [enabled, blockWhile, now, nextRefreshAt, runRefresh]);

  const refreshNow = useCallback(async () => {
    await runRefresh();
  }, [runRefresh]);

  const resetTimer = useCallback(() => {
    setNextRefreshAt(Date.now() + intervalSeconds * 1000);
  }, [intervalSeconds]);

  return { secondsRemaining, refreshNow, resetTimer };
}
