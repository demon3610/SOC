import { PageHeader } from '../components/ui/PageHeader';

const BODY = 'text-sm text-soc-muted text-justify hyphens-auto leading-relaxed';

export function HelpPage() {
  return (
    <div lang="en" className="max-w-3xl mx-auto py-10">
      <PageHeader title="Help & Documentation" />
      <div className="space-y-5">
        <section className="glass-card rounded-xl p-5">
          <h2 className="text-lg font-semibold mb-3 text-soc-text">Getting Started</h2>
          <p className={BODY}>
            Create a Project from the Workspace, then follow the integration instructions
            to connect a website or system. Events will begin flowing into Live Events.
          </p>
        </section>
        <section className="glass-card rounded-xl p-5">
          <h2 className="text-lg font-semibold mb-3 text-soc-text">Projects</h2>
          <p className={BODY}>
            Each Project represents a monitored surface. A website project uses a JavaScript
            snippet; a system project uses our Windows PowerShell or Linux shell agent.
          </p>
        </section>
        <section className="glass-card rounded-xl p-5">
          <h2 className="text-lg font-semibold mb-3 text-soc-text">Incidents</h2>
          <p className={BODY}>
            When you see suspicious activity, create an Incident and attach the relevant
            event as evidence. Incidents can be investigated, updated, and resolved.
          </p>
        </section>
        <section className="glass-card rounded-xl p-5">
          <h2 className="text-lg font-semibold mb-3 text-soc-text">API Keys</h2>
          <p className={BODY}>
            Each project can have multiple API keys for different sources. Keys are shown
            once at creation. Revoke compromised keys immediately. Website keys are
            ingest-only and rate-limited.
          </p>
        </section>
        <section className="glass-card rounded-xl p-5">
          <h2 className="text-lg font-semibold mb-3 text-soc-text">Agents</h2>
          <div className="space-y-3">
            <div className="bg-soc-card border border-soc-border/60 rounded-lg p-4">
              <p className={BODY}>
                <strong className="font-semibold text-soc-text">usp.js</strong> - Browser snippet that captures page views and JS errors
                every 5 seconds (or 20 events). Requires data-soc-key and data-soc-project attributes.
              </p>
            </div>
            <div className="bg-soc-card border border-soc-border/60 rounded-lg p-4">
              <p className={BODY}>
                <strong className="font-semibold text-soc-text">Windows Agent (install.ps1)</strong> - Scheduled Task that tails Event Logs
                (Security, Application, System) and specified log files every 5 minutes.
              </p>
            </div>
            <div className="bg-soc-card border border-soc-border/60 rounded-lg p-4">
              <p className={BODY}>
                <strong className="font-semibold text-soc-text">Linux Agent (install.sh)</strong> - Systemd timer (or cron fallback) that
                tails configured log files every 5 minutes.
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}