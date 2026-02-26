import { create } from 'zustand';
import type { Artifact } from '../types';

interface ArtifactState {
  artifacts: Artifact[];
  addArtifact: (artifact: Artifact) => void;
  removeArtifact: (id: string) => void;
  downloadArtifact: (id: string) => void;
  clearAll: () => void;
}

export const useArtifactStore = create<ArtifactState>((set, get) => ({
  artifacts: [],

  addArtifact: (artifact) => {
    set((s) => ({ artifacts: [artifact, ...s.artifacts] }));
  },

  removeArtifact: (id) => {
    set((s) => ({ artifacts: s.artifacts.filter((a) => a.id !== id) }));
  },

  downloadArtifact: (id) => {
    const artifact = get().artifacts.find((a) => a.id === id);
    if (!artifact) return;

    const binary = atob(artifact.data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = artifact.name;
    a.click();
    URL.revokeObjectURL(url);
  },

  clearAll: () => set({ artifacts: [] }),
}));
