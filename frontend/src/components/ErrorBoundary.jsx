import React from 'react';
import { ShieldAlert } from 'lucide-react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Uncaught UI error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-soc-bg flex flex-col items-center justify-center p-6 text-center">
          <div className="glass-card rounded-xl p-8 max-w-md w-full">
            <ShieldAlert size={28} strokeWidth={1.5} className="text-slate-400 mb-4 mx-auto" />
            <h2 className="text-xl font-bold text-soc-text mb-2">Something went wrong</h2>
            <p className="text-sm text-soc-muted mb-4">
              {this.state.error?.message || "An unexpected error occurred in the dashboard UI."}
            </p>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.href = '/workspace';
              }}
              className="bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm transition-colors"
            >
              Return to Workspace
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
