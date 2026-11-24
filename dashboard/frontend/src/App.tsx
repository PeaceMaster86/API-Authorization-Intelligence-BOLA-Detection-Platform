import { useEffect, useMemo, useState } from "react";
import { loadEndpoints, loadObjects, loadReport } from "./api";
import type { Endpoint, ObjectRecord, Report } from "./types";

type LoadState<T> = { data: T | null; error: string | null; loading: boolean };

function useResource<T>(loader: () => Promise<T>): LoadState<T> {
  const [state, setState] = useState<LoadState<T>>({
    data: null,
    error: null,
    loading: true,
  });
  useEffect(() => {
    let active = true;
    loader()
      .then((data) => active && setState({ data, error: null, loading: false }))
      .catch((error: unknown) => {
        if (active) {
          setState({
            data: null,
            error: error instanceof Error ? error.message : "Request failed",
            loading: false,
          });
        }
      });
    return () => {
      active = false;
    };
  }, [loader]);
  return state;
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function App() {
  const report = useResource<Report>(loadReport);
  const endpoints = useResource<Endpoint[]>(loadEndpoints);
  const objects = useResource<ObjectRecord[]>(loadObjects);
  const [activeView, setActiveView] = useState<"overview" | "inventory" | "findings">("overview");
  const findings = report.data?.findings ?? [];
  const confirmed = report.data?.summary.confirmed ?? 0;
  const severity = useMemo(() => report.data?.summary.severity ?? {}, [report.data]);

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">AI</span><div><strong>AUTHZ INTEL</strong><small>Security workspace</small></div></div>
        <nav aria-label="Primary navigation">
          {(["overview", "inventory", "findings"] as const).map((view) => (
            <button className={activeView === view ? "nav-item active" : "nav-item"} onClick={() => setActiveView(view)} key={view}>
              {view[0].toUpperCase() + view.slice(1)}
            </button>
          ))}
        </nav>
        <div className="scope-note"><span className="status-dot" /> Local lab scope</div>
      </aside>
      <section className="content">
        <header className="topbar"><div><p className="eyebrow">Authorization intelligence</p><h1>{activeView === "overview" ? "Dashboard overview" : activeView === "inventory" ? "API inventory" : "Findings"}</h1></div><span className="scope-pill">Evidence-backed data</span></header>
        {report.error && <div className="alert">Report unavailable: {report.error}. Generate a report with the scanner to populate this view.</div>}
        {activeView === "overview" && (
          <>
            <section className="metrics">
              <Metric label="Total findings" value={report.data?.summary.total ?? 0} />
              <Metric label="Confirmed" value={confirmed} />
              <Metric label="High severity" value={severity.high ?? 0} />
              <Metric label="Endpoints discovered" value={endpoints.data?.length ?? 0} />
            </section>
            <section className="panel-grid">
              <article className="panel"><div className="panel-heading"><h2>Recent findings</h2><button className="text-button" onClick={() => setActiveView("findings")}>View all</button></div><FindingTable findings={findings.slice(0, 5)} loading={report.loading} /></article>
              <article className="panel"><div className="panel-heading"><h2>Object registry</h2><span className="muted">{objects.data?.length ?? 0} objects</span></div><ObjectTable objects={(objects.data ?? []).slice(0, 5)} loading={objects.loading} /></article>
            </section>
          </>
        )}
        {activeView === "inventory" && <article className="panel full-panel"><div className="panel-heading"><h2>Discovered endpoints</h2><span className="muted">{endpoints.data?.length ?? 0} endpoints</span></div><EndpointTable endpoints={endpoints.data ?? []} loading={endpoints.loading} error={endpoints.error} /></article>}
        {activeView === "findings" && <article className="panel full-panel"><div className="panel-heading"><h2>Verified findings</h2><span className="muted">{findings.length} findings</span></div><FindingTable findings={findings} loading={report.loading} /></article>}
      </section>
    </main>
  );
}

function FindingTable({ findings, loading }: { findings: Report["findings"]; loading: boolean }) {
  if (loading) return <p className="empty">Loading evidence...</p>;
  if (!findings.length) return <p className="empty">No findings in the loaded report.</p>;
  return <div className="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th><th>Principal</th><th>Verification</th></tr></thead><tbody>{findings.map((finding) => <tr key={finding.finding_id}><td><strong>{finding.title}</strong><small>{finding.method} {finding.endpoint}</small></td><td><span className={`badge ${finding.severity}`}>{finding.severity}</span></td><td>{finding.principal}</td><td>{finding.verification_result}</td></tr>)}</tbody></table></div>;
}

function ObjectTable({ objects, loading }: { objects: ObjectRecord[]; loading: boolean }) {
  if (loading) return <p className="empty">Loading objects...</p>;
  if (!objects.length) return <p className="empty">Object inventory is unavailable.</p>;
  return <div className="table-wrap"><table><thead><tr><th>Object</th><th>Owner</th><th>Tenant</th></tr></thead><tbody>{objects.map((object) => <tr key={`${object.resource_type}-${object.object_id}`}><td>{object.resource_type}/{object.object_id}</td><td>{object.owner}</td><td>{object.tenant_id}</td></tr>)}</tbody></table></div>;
}

function EndpointTable({ endpoints, loading, error }: { endpoints: Endpoint[]; loading: boolean; error: string | null }) {
  if (loading) return <p className="empty">Loading endpoint inventory...</p>;
  if (error) return <p className="empty">Endpoint inventory unavailable: {error}</p>;
  if (!endpoints.length) return <p className="empty">No endpoint inventory has been published.</p>;
  return <div className="table-wrap"><table><thead><tr><th>Method</th><th>Path</th><th>Object parameters</th><th>Capability</th></tr></thead><tbody>{endpoints.map((endpoint) => <tr key={`${endpoint.method}-${endpoint.path}`}><td><span className="method">{endpoint.method}</span></td><td>{endpoint.path}</td><td>{endpoint.object_parameters.join(", ") || "—"}</td><td>{endpoint.testing_capability}</td></tr>)}</tbody></table></div>;
}

export default App;
