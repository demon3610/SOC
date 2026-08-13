export function FooterBar() {
  return (
    <footer className="h-9 bg-white border-t border-soc-border flex items-center px-6 ml-60 max-lg:ml-0 text-xs text-soc-muted">
      <span className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-soc-sage" />
        Ingest: OK
      </span>
      <span className="mx-3 text-soc-border">|</span>
      <span className="flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-soc-sage" />
        ES Cluster: Connected
      </span>
    </footer>
  );
}
