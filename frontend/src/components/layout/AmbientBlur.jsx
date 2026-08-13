export function AmbientBlur() {
  return (
    <div className="fixed inset-0 pointer-events-none overflow-hidden -z-10">
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-soc-accent/10 rounded-full blur-[128px]" />
      <div className="absolute top-1/3 -right-32 w-80 h-80 bg-soc-accent-glow/10 rounded-full blur-[128px]" />
      <div className="absolute -bottom-32 left-1/4 w-72 h-72 bg-sky-400/10 rounded-full blur-[128px]" />
    </div>
  );
}
