// Shared app state: which analysis the workspace is pointed at, plus the
// reference data every page needs. The selected analysis id survives a reload
// (localStorage) so the team lands back where they were.

import { api } from "./api.js";

const KEY = "fwa-current-analysis";

const state = {
  meta: null,          // vendors / risk levels / issue types
  current: null,       // the selected analysis record
  analyses: [],        // recent analyses, for the picker
};

const listeners = new Set();

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit() {
  listeners.forEach((fn) => fn(state));
}

export function getState() {
  return state;
}

export async function loadMeta() {
  if (!state.meta) state.meta = await api.meta();
  return state.meta;
}

export async function refreshAnalyses() {
  const { items } = await api.analyses(50);
  state.analyses = items;
  emit();
  return items;
}

/** Point the workspace at an analysis; null clears it. */
export async function selectAnalysis(id) {
  if (!id) {
    state.current = null;
    localStorage.removeItem(KEY);
    emit();
    return null;
  }
  state.current = await api.analysis(id);
  localStorage.setItem(KEY, id);
  emit();
  return state.current;
}

/** Re-fetch the selected analysis — used while a run is in flight. */
export async function refreshCurrent() {
  if (!state.current) return null;
  state.current = await api.analysis(state.current.id);
  emit();
  return state.current;
}

/**
 * Restore the previous selection, falling back to the most recent successful
 * analysis so a first-time visitor still lands on something real.
 */
export async function restoreSelection() {
  const saved = localStorage.getItem(KEY);
  const items = await refreshAnalyses();

  if (saved && items.some((a) => a.id === saved)) {
    try { return await selectAnalysis(saved); } catch { /* fall through */ }
  }
  const newest = items.find((a) => a.status === "succeeded");
  if (newest) return selectAnalysis(newest.id);

  localStorage.removeItem(KEY);
  emit();
  return null;
}
