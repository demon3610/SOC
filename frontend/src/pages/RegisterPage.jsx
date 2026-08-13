import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';

export function RegisterPage() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const register = useAuthStore((s) => s.register);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await register(email, password, name);
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
          <h1 className="text-xl font-bold text-soc-text mt-3">Create Account</h1>
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-soc-muted mt-0.5">
            SOC Operations Center
          </p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-sm text-soc-muted block mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-white border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent focus:ring-1 focus:ring-soc-accent/25"
              required
            />
          </div>
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
              minLength={6}
            />
          </div>
          {error && <p className="text-red-600 text-sm">{error}</p>}
          <button
            type="submit"
            className="w-full bg-soc-accent hover:bg-soc-accent-glow text-white rounded-lg py-2 text-sm font-medium transition-colors"
          >
            Register
          </button>
        </form>
        <p className="text-center text-sm text-soc-muted mt-4">
          Already have an account?{' '}
          <Link to="/login" className="text-soc-accent hover:underline">
            Log in
          </Link>
        </p>
      </div>
    </div>
  );
}
