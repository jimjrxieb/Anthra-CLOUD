import { useState } from "react";

const API = "/api";

export default function App() {
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [searchHtml, setSearchHtml] = useState("");
  const [tenantId, setTenantId] = useState("tenant-1");

  async function fetchLogs() {
    const res = await fetch(`${API}/logs?tenant_id=${tenantId}`);
    const data = await res.json();
    setLogs(data.logs || []);
  }

  async function doSearch() {
    // VULN: renders raw HTML from server (XSS)
    const res = await fetch(`${API}/search?q=${encodeURIComponent(search)}`);
    const html = await res.text();
    setSearchHtml(html);
  }

  return (
    <div style={{ fontFamily: "monospace", padding: 24, maxWidth: 900, margin: "0 auto" }}>
      <h1>NovaSec Cloud</h1>
      <p style={{ color: "#888" }}>Security Monitoring Dashboard</p>

      <section style={{ marginBottom: 32 }}>
        <h2>Log Viewer</h2>
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <input
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            placeholder="Tenant ID"
            style={{ padding: 6, fontFamily: "monospace" }}
          />
          <button onClick={fetchLogs}>Fetch Logs</button>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #ccc", textAlign: "left" }}>
              <th>ID</th><th>Tenant</th><th>Level</th><th>Message</th><th>Source</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((l, i) => (
              <tr key={i} style={{ borderBottom: "1px solid #eee" }}>
                <td>{l.id}</td>
                <td>{l.tenant_id}</td>
                <td>{l.level}</td>
                <td>{l.message}</td>
                <td>{l.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Search</h2>
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search logs..."
            style={{ padding: 6, fontFamily: "monospace", flex: 1 }}
          />
          <button onClick={doSearch}>Search</button>
        </div>
        {/* VULN: dangerouslySetInnerHTML renders server XSS payloads */}
        <div dangerouslySetInnerHTML={{ __html: searchHtml }} />
      </section>
    </div>
  );
}
