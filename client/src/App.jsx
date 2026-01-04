// client/src/App.jsx (TLS 1.3 ONLY - Requirement 2a)
import { useEffect, useState } from "react";

const API = "https://localhost:4000";

export default function App() {
  const [file, setFile] = useState(null);
  const [files, setFiles] = useState([]);
  const [status, setStatus] = useState("");

  async function refresh() {
    const res = await fetch(`${API}/files`);
    const data = await res.json();
    setFiles(Array.isArray(data) ? data : []);
  }

  useEffect(() => {
    refresh();
  }, []);

  async function uploadFile(e) {
    e.preventDefault();
    if (!file) return;

    try {
      setStatus("Uploading over TLS 1.3…");

      const form = new FormData();
      form.append("file", file); // plaintext file; TLS encrypts in transit

      const r = await fetch(`${API}/upload`, { method: "POST", body: form });
      const data = await r.json();

      if (!r.ok) {
        setStatus(data?.error || "Upload failed");
        return;
      }

      setStatus(`Uploaded: ${data.name}`);
      setFile(null);
      await refresh();
    } catch (err) {
      console.error(err);
      setStatus("Upload failed (TLS)");
    }
  }

  return (
    <div style={{ padding: 20, fontFamily: "system-ui" }}>
      <h2>File Upload + Download (TLS 1.3)</h2>

      <form onSubmit={uploadFile} style={{ marginBottom: 16 }}>
        <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
        <button type="submit" style={{ marginLeft: 8 }}>Upload</button>
      </form>

      <div style={{ marginBottom: 16 }}>{status}</div>

      <h3>Files</h3>
      <ul>
        {files.map((f) => (
          <li key={f.id}>
            {f.originalName} ({Math.round((f.size || 0) / 1024)} KB) —{" "}
            <a href={`${API}/files/${f.id}`}>Download</a>
          </li>
        ))}
      </ul>
    </div>
  );
}
