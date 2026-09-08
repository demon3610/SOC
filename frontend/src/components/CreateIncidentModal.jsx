import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { api } from '../lib/api';

const SEVERITIES = ['low', 'medium', 'high', 'critical'];

export function CreateIncidentModal({ open, event, projectId, onClose, initialSeverity, initialTitle, initialDescription }) {
  const [title, setTitle] = useState(initialTitle || '');
  const [description, setDescription] = useState(initialDescription || '');
  const [severity, setSeverity] = useState('medium');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (open) {
      setSeverity(SEVERITIES.includes(initialSeverity) ? initialSeverity : 'medium');
      if (initialTitle) setTitle(initialTitle);
      if (initialDescription) setDescription(initialDescription);
    }
  }, [open, initialSeverity, initialTitle, initialDescription]);

  if (!open) return null;

  const handleCreate = async () => {
    setLoading(true);
    try {
      await api.incidents.create(projectId, { title, severity, description: description || null });
      onClose();
    } catch {}
    setLoading(false);
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-soc-overlay/60"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.9 }}
        animate={{ scale: 1 }}
        className="glass-elevated rounded-xl p-6 w-full max-w-md mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold mb-1 text-soc-slate">
          {event ? 'Create Incident from Event' : 'Create New Incident'}
        </h2>
        {event && (
          <p className="text-xs text-soc-muted mb-4 break-words">
            {event.summary || event.raw?.message || event.id}
          </p>
        )}
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Incident title"
          className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm mb-3 focus:outline-none focus:border-soc-accent"
        />
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Description (optional)"
          rows={4}
          className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm mb-3 focus:outline-none focus:border-soc-accent resize-none"
        />
        <div className="flex gap-2 mb-4">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s)}
              className={`px-3 py-1.5 rounded text-xs border ${
                severity === s
                  ? 'bg-soc-accent border-soc-accent text-soc-on-accent'
                  : 'bg-soc-card border-soc-border text-soc-muted'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="text-sm text-soc-muted">Cancel</button>
          <button
            onClick={handleCreate}
            disabled={!title || loading}
            className="bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm disabled:opacity-50"
          >
            {loading ? 'Creating...' : 'Create Incident'}
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}
