import { Status, STATUS_LABEL } from "@/lib/api";

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm whitespace-nowrap">
      <span aria-hidden className={`st-${status} inline-block h-2.5 w-2.5 rounded-[3px]`} />
      {STATUS_LABEL[status]}
    </span>
  );
}

export function Legend() {
  const order: Status[] = ["MET", "NOT_MET", "INSUFFICIENT_EVIDENCE", "NOT_ASSESSED", "NOT_APPLICABLE"];
  return (
    <ul className="flex flex-wrap gap-x-5 gap-y-1.5 text-sm text-steel">
      {order.map((s) => <li key={s}><StatusBadge status={s} /></li>)}
    </ul>
  );
}

export function AiLabel({ children = "AI suggestion, not a result" }: { children?: React.ReactNode }) {
  return <span className="text-[13px] font-semibold text-ai">{children}</span>;
}

export function Empty({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-line bg-panel p-8 text-center">
      <p className="font-semibold">{title}</p>
      {children && <div className="mt-2 text-steel">{children}</div>}
    </div>
  );
}
