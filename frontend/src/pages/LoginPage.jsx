import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';

export function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const login = useAuthStore((s) => s.login);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await login(email, password);
      navigate('/workspace');
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-soc-bg">
      <div className="glass-card rounded-xl p-8 w-full max-w-sm">
        <div className="flex flex-col items-center mb-6">
          <span className="w-12 h-12 rounded-xl bg-soc-tint-steel border border-soc-accent/20 flex items-center justify-center">
            <Shield size={24} className="text-soc-accent" strokeWidth={2.2} />
          </span>
          <h1 className="text-xl font-bold text-soc-text mt-3">SOC</h1>
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-soc-muted mt-0.5">
            Operations Center
          </p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-sm text-soc-muted block mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-white border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent focus:ring-1 focus:ring-soc-accent/25"
              required
            />
          </div>
          <div>
            <label className="text-sm text-soc-muted block mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-white border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent focus:ring-1 focus:ring-soc-accent/25"
              required
            />
          </div>
          {error && <p className="text-red-600 text-sm">{error}</p>}
          <button
            type="submit"
            className="w-full bg-soc-accent hover:bg-soc-accent-glow text-white rounded-lg py-2 text-sm font-medium transition-colors"
          >
            Log in
          </button>
        </form>
        <p className="text-center text-sm text-soc-muted mt-4">
          No account?{' '}
          <Link to="/register" className="text-soc-accent hover:underline">
            Register
          </Link>
        </p>
      </div>
    </div>
  );
}
