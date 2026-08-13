import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { Plus, Trash2, ArrowRight } from "lucide-react";
import { api } from "../lib/api";
import { useProjectStore } from "../stores/projectStore";
import { useToastStore } from "../stores/toastStore";
import { NewProjectModal } from "../components/projects/NewProjectModal";
import { PageHeader } from "../components/ui/PageHeader";
import { formatLocalDate } from "../lib/time";

function projectStatus(p) {
  if (!p?.last_event_time)
    return {
      label: "INACTIVE",
      cls: "bg-soc-tint-neutral text-soc-muted border-soc-border",
    };
  const ageDays =
    (Date.now() - new Date(p.last_event_time).getTime()) / 86400000;
  return ageDays <= 30
    ? { label: "ACTIVE", cls: "bg-green-50 text-green-700 border-green-200" }
    : {
        label: "INACTIVE",
        cls: "bg-soc-tint-neutral text-soc-muted border-soc-border",
      };
}

const TYPE_BADGE = {
  website: "badge-website",
  linux: "badge-linux",
  windows: "badge-linux",
  system: "badge-system",
};

export function WorkspacePage() {
  const [showModal, setShowModal] = useState(false);
  const [deletingId, setDeletingId] = useState(null);
  const setActiveProject = useProjectStore((s) => s.setActiveProject);
  const activeProject = useProjectStore((s) => s.activeProject);
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const navigate = useNavigate();

  const { data: projects, refetch } = useQuery({
    queryKey: ["projects"],
    queryFn: () => api.projects.list(),
  });

  const deleteMutation = useMutation({
    mutationFn: (id) => api.projects.delete(id),
    onSuccess: (_, id) => {
      if (activeProject?.id === id) setActiveProject(null);
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      addToast("Project deleted", "success");
    },
    onError: (err) => {
      addToast(err.message, "error");
    },
  });

  const openProject = (p) => {
    setActiveProject(p);
    navigate(`/projects/${p.id}/overview`);
  };

  return (
    <div>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {projects?.map((p) => {
          const status = projectStatus(p);
          const isActive = activeProject?.id === p.id;
          return (
            <motion.div
              key={p.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className={`bg-white rounded-xl border shadow-lift p-5 flex flex-col group ${
                isActive
                  ? "border-soc-accent/60 ring-2 ring-soc-accent/25"
                  : "border-soc-border"
              }`}
            >
              <div className="flex items-center justify-between gap-3 mb-1">
                <h3 className="font-bold text-soc-text truncate">{p.name}</h3>
                <div className="flex items-center gap-2 shrink-0">
                  <span
                    className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${status.cls}`}
                  >
                    {status.label}
                  </span>
                  <span
                    className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full ${TYPE_BADGE[p.type] || "badge-system"}`}
                  >
                    {p.type}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setDeletingId(deletingId === p.id ? null : p.id);
                    }}
                    className="text-soc-muted/50 hover:text-soc-critical transition-colors"
                    title="Delete project"
                    aria-label={`Delete project ${p.name}`}
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>

              <p className="text-sm text-soc-muted mb-4 flex-1 line-clamp-2">
                {p.description || "No description provided"}
              </p>

              <div className="flex items-center justify-between border-t border-soc-border/70 pt-3">
                <span className="flex items-center gap-2 text-xs text-soc-muted">
                  <span className="w-1.5 h-1.5 rounded-full bg-soc-sage" />
                  {p.last_event_time
                    ? formatLocalDate(p.last_event_time)
                    : "No events yet"}
                </span>
                <button
                  onClick={() => openProject(p)}
                  className="flex items-center gap-1 text-xs font-semibold text-soc-accent/70 hover:text-soc-accent transition-colors"
                >
                  Open Workspace
                  <ArrowRight size={13} />
                </button>
              </div>

              <AnimatePresence>
                {deletingId === p.id && (
                  <motion.div
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 4 }}
                    className="mt-3 flex items-center gap-2 justify-end border-t border-soc-border/70 pt-3"
                  >
                    <span className="text-xs text-soc-muted">
                      Delete this project?
                    </span>
                    <button
                      onClick={() => setDeletingId(null)}
                      className="text-xs text-soc-muted hover:text-soc-accent px-2 py-1"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => {
                        deleteMutation.mutate(p.id);
                        setDeletingId(null);
                      }}
                      disabled={deleteMutation.isPending}
                      className="text-xs bg-red-500/10 text-red-600 hover:bg-red-500/15 border border-red-200 px-2.5 py-1 rounded-lg disabled:opacity-50"
                    >
                      {deleteMutation.isPending &&
                      deleteMutation.variables === p.id
                        ? "Deleting..."
                        : "Delete"}
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          );
        })}

        <button
          onClick={() => setShowModal(true)}
          className="border-2 border-dashed border-soc-border rounded-xl p-5 min-h-[168px] flex items-center justify-center hover:border-soc-accent/60 hover:bg-soc-tint-steel/40 transition-colors group"
        >
          <div className="text-center">
            <span className="w-10 h-10 mx-auto mb-2.5 rounded-full bg-soc-tint-steel border border-soc-accent/20 flex items-center justify-center">
              <Plus size={20} className="text-soc-accent" />
            </span>
            <span className="block text-sm font-bold text-soc-text">
              New Project
            </span>
            <span className="block text-xs text-soc-muted mt-0.5">
              Create dedicated workspace
            </span>
          </div>
        </button>
      </div>

      <AnimatePresence>
        {showModal && (
          <NewProjectModal
            onClose={() => setShowModal(false)}
            onCreated={(project) => {
              setActiveProject(project);
              refetch();
              setShowModal(false);
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
