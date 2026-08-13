import { motion, AnimatePresence } from 'framer-motion';
import { useToastStore } from '../../stores/toastStore';
import { X } from 'lucide-react';

const TYPE_STYLES = {
  success: 'border-green-600/30 bg-green-600/10 text-green-700',
  error: 'border-red-500/35 bg-red-500/10 text-red-600',
  info: 'border-soc-accent/40 bg-soc-accent/10 text-soc-accent',
};

export function Toaster() {
  const toasts = useToastStore((s) => s.toasts);
  const removeToast = useToastStore((s) => s.removeToast);

  return (
    <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
      <AnimatePresence>
        {toasts.map((t) => (
          <motion.div
            key={t.id}
            initial={{ opacity: 0, x: 80, scale: 0.9 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 80, scale: 0.9 }}
            transition={{ type: 'spring', stiffness: 400, damping: 30 }}
            className={`pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-xl border backdrop-blur-xl shadow-storm min-w-[280px] max-w-md ${TYPE_STYLES[t.type]}`}
          >
            <span className="text-sm flex-1">{t.message}</span>
            <button
              onClick={() => removeToast(t.id)}
              className="shrink-0 opacity-60 hover:opacity-100 transition-opacity"
              aria-label="Dismiss"
            >
              <X size={16} />
            </button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}
