import { useEffect, useState, useMemo } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:4000";

export default function App() {
  const [serverFiles, setServerFiles] = useState([]); 
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const api = useMemo(() => ({
    async list() {
      const res = await fetch(`${API_BASE}/api/files`, { mode: "cors" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      return Array.isArray(data?.files) ? data.files : [];
    },
    async upload(file) {
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch(`${API_BASE}/api/upload`, {
        method: "POST",
        body: fd,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  }), []);

  async function refresh() {
    setErr("");
    setLoading(true);
    try {
      const files = await api.list();
      setServerFiles(files);
    } catch (e) {
      console.error("fetch /api/files failed:", e);
      setErr(String(e.message || e));
      setServerFiles([]); 
    } finally {
      setLoading(false);
    }
  }

  async function onUpload(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    setErr("");
    setLoading(true);
    try {
      await api.upload(f);
      await refresh();
    } catch (e) {
      console.error("upload failed:", e);
      setErr(String(e.message || e));
    } finally {
      setLoading(false);
      e.target.value = ""; 
    }
  }

  useEffect(() => { refresh(); }, []);

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", maxWidth: 800, margin: "40px auto", padding: 16 }}>
      <h1>Secure Remote Storage (Demo)</h1>

      <div style={{ margin: "16px 0" }}>
        <label style={{ display: "inline-block", padding: "8px 12px", border: "1px solid #ddd", borderRadius: 8, cursor: "pointer" }}>
          Upload file
          <input type="file" style={{ display: "none" }} onChange={onUpload} />
        </label>
        <button onClick={refresh} style={{ marginLeft: 12, padding: "8px 12px", borderRadius: 8 }}>
          Refresh
        </button>
      </div>

      <div style={{ margin: "8px 0", color: "#666" }}>
        API: <code>{API_BASE}</code>
      </div>

      {loading && <div>Loading…</div>}
      {err && <div style={{ color: "crimson", marginTop: 8 }}>Error: {err}</div>}

      <h2 style={{ marginTop: 24 }}>Server files</h2>
      {serverFiles.length === 0 ? (
        <div style={{ color: "#888" }}>No files</div>
      ) : (
        <ul style={{ paddingLeft: 18 }}>
          {serverFiles.map((f) => (
            <li key={f.name ?? `${f.path}-${f.size}`}>
              <strong>{f.name || f.path}</strong>
              {typeof f.size === "number" ? ` — ${f.size} bytes` : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
