export function PageHeader({ title, right }) {
  return (
    <div className="flex items-start justify-between gap-4 mb-6 flex-wrap">
      <h1 className="text-xl font-bold text-soc-text">{title}</h1>
      {right && <div className="flex items-center gap-3">{right}</div>}
    </div>
  );
}
