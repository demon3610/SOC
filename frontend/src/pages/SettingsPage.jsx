import { useAuthStore } from '../stores/authStore';
import { PageHeader } from '../components/ui/PageHeader';

export function SettingsPage() {
  const user = useAuthStore((s) => s.user);

  return (
    <div className="max-w-2xl mx-auto">
      <PageHeader title="Settings" />

      <div className="glass-card rounded-xl p-5">
        <h2 className="font-semibold mb-3 text-soc-text">Account</h2>
        <div className="space-y-2 text-sm text-soc-muted">
          <div className="flex justify-between border-b border-soc-border/60 pb-2">
            <span>Name</span>
            <span className="text-soc-text font-medium">{user?.name || user?.email}</span>
          </div>
          <div className="flex justify-between border-b border-soc-border/60 pb-2">
            <span>Email</span>
            <span className="text-soc-text font-medium">{user?.email}</span>
          </div>
          <div className="flex justify-between">
            <span>Member since</span>
            <span className="text-soc-text font-medium">
              {user?.created_at ? new Date(user.created_at).toLocaleDateString() : '-'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
