import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';

export function ExplorePage() {
  return (
    <div className="min-h-screen bg-soc-bg flex items-center justify-center">
      <div className="glass-card rounded-xl p-8 w-full max-w-lg text-center">
        <span className="w-14 h-14 mx-auto rounded-xl bg-soc-tint-steel border border-soc-accent/20 flex items-center justify-center">
          <Shield size={28} className="text-soc-accent" strokeWidth={2.2} />
        </span>
        <h1 className="text-3xl font-bold mt-4 text-soc-text">SOC Platform</h1>
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-soc-muted mt-1">
          Operations Center
        </p>
        <p className="text-soc-muted mt-6 mb-8">
          Security operations center monitoring platform.
        </p>
        <div className="flex gap-4 justify-center">
          <Link
            to="/login"
            className="bg-soc-accent hover:bg-soc-accent-glow text-white rounded-lg px-6 py-2 text-sm font-medium transition-colors"
          >
            Log in
          </Link>
          <Link
            to="/register"
            className="border border-soc-border hover:border-soc-accent/50 text-soc-muted hover:text-soc-accent rounded-lg px-6 py-2 text-sm font-medium transition-colors"
          >
            Register
          </Link>
        </div>
      </div>
    </div>
  );
}
