/**
 * PortScanner.jsx
 *
 * SECURITY REQUIREMENTS enforced in this component:
 *   1. Authorization checkbox MUST be checked before scan button is enabled.
 *   2. `authorized: true` is sent in the POST body — backend enforces this too.
 *   3. Scan button is disabled and shows a tooltip while unchecked.
 *   4. Port list is validated client-side before sending (must be 1..65535, ≤1024).
 */

import { useState } from "react";
import axios from "axios";
import { getTargetValidationError } from "./portValidation";

const API_BASE = (
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000"
).replace(/\/$/, "");
const API = `${API_BASE}/api`;

const DEFAULT_PORTS_STR = "21,22,23,25,53,80,110,143,443,3306,3389,8080";

function parsePorts(str) {
  const nums = str
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean)
    .map(Number)
    .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);
  return [...new Set(nums)]; // deduplicate
}

function StatusBadge({ open }) {
  return open ? (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
      ● OPEN
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-white/5 text-gray-500 border border-white/10">
      ● CLOSED
    </span>
  );
}

function ResultsTable({ results }) {
  const open = results.filter((r) => r.open);
  const closed = results.filter((r) => !r.open);

  return (
    <div className="space-y-4">
      <div className="flex gap-4 text-sm">
        <span className="text-emerald-400 font-semibold">
          {open.length} open
        </span>
        <span className="text-gray-500">{closed.length} closed</span>
        <span className="text-gray-500">{results.length} total</span>
      </div>

      <div className="overflow-x-auto max-h-80 overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-gray-950/80 backdrop-blur-sm">
            <tr className="text-gray-500 text-xs border-b border-white/5">
              <th className="text-left py-2 pr-4 font-medium">Port</th>
              <th className="text-left py-2 pr-4 font-medium">Status</th>
              <th className="text-left py-2 font-medium">Banner</th>
            </tr>
          </thead>
          <tbody>
            {/* Show open ports first */}
            {[...open, ...closed].map((r) => (
              <tr key={r.port} className="scan-row border-b border-white/5">
                <td className="py-2 pr-4 font-mono text-gray-200">{r.port}</td>
                <td className="py-2 pr-4">
                  <StatusBadge open={r.open} />
                </td>
                <td className="py-2 text-gray-400 font-mono text-xs max-w-xs truncate">
                  {r.banner || (r.open ? "—" : "")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function HistoryTable({ rows }) {
  if (!rows.length)
    return (
      <p className="text-gray-500 text-sm text-center py-4">
        No scan history saved yet.
      </p>
    );
  return (
    <div className="space-y-3">
      {rows.map((r) => (
        <div
          key={r.id}
          className="bg-white/3 rounded-xl p-4 border border-white/5"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono text-cyan-400 text-sm">{r.target}</span>
            <span className="text-gray-500 text-xs">
              {new Date(r.timestamp).toLocaleString()}
            </span>
          </div>
          <div className="text-xs text-gray-400">
            Open ports:{" "}
            {r.open_ports.length ? (
              r.open_ports.map((p) => (
                <span
                  key={p}
                  className="inline-block mr-1 px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono"
                >
                  {p}
                </span>
              ))
            ) : (
              <span className="text-gray-600">none</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function PortScanner() {
  const [target, setTarget] = useState("");
  const [portsStr, setPortsStr] = useState(DEFAULT_PORTS_STR);
  const [authorized, setAuthorized] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [lastScanMeta, setLastScanMeta] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState(null);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [histLoading, setHistLoading] = useState(false);

  const ports = parsePorts(portsStr);
  const portError =
    ports.length === 0
      ? "Enter at least one valid port (1–65535)"
      : ports.length > 1024
        ? "Maximum 1024 ports per scan"
        : null;
  const targetError = getTargetValidationError(target);

  const canScan = authorized && !targetError && !portError;

  const handleScan = async () => {
    const validationError = getTargetValidationError(target);
    if (validationError) {
      setError(validationError);
      return;
    }

    setError(null);
    setResults(null);
    setSaveMsg(null);
    setScanning(true);
    try {
      const resp = await axios.post(`${API}/scan`, {
        target: target.trim(),
        ports,
        authorized: true, // checkbox was required to enable this button
        timeout: 1.0,
      });
      setResults(resp.data.results);
      setLastScanMeta({
        target: target.trim(),
        open_ports: resp.data.open_ports,
        banners: Object.fromEntries(
          (resp.data.results || [])
            .filter((r) => r.open && r.banner)
            .map((r) => [String(r.port), r.banner]),
        ),
      });
    } catch (err) {
      const detail = err?.response?.data?.detail;
      if (typeof detail === "string") {
        setError(detail);
      } else if (Array.isArray(detail)) {
        setError(detail.map((d) => d.msg).join("; "));
      } else {
        setError("Scan failed. Check that the backend is running.");
      }
    } finally {
      setScanning(false);
    }
  };

  const handleSaveResult = async () => {
    if (!lastScanMeta) return;
    setSaving(true);
    setSaveMsg(null);
    try {
      await axios.post(`${API}/scan/save-result`, lastScanMeta);
      setSaveMsg({ ok: true, text: "Scan result saved (encrypted)." });
      if (showHistory) fetchHistory();
    } catch (err) {
      setSaveMsg({
        ok: false,
        text: err?.response?.data?.detail ?? "Save failed.",
      });
    } finally {
      setSaving(false);
    }
  };

  const fetchHistory = async () => {
    setHistLoading(true);
    try {
      const res = await axios.get(`${API}/scan/history`);
      setHistory(res.data);
    } catch {
      setHistory([]);
    } finally {
      setHistLoading(false);
    }
  };

  const toggleHistory = () => {
    const next = !showHistory;
    setShowHistory(next);
    if (next) fetchHistory();
  };

  return (
    <div className="space-y-6">
      {/* Legal warning banner */}
      <div className="glass-card p-4 border-l-4 border-amber-500 text-sm text-gray-300">
        <span className="font-semibold text-amber-400">⚠ Legal Notice:</span>{" "}
        Only scan systems you own or have{" "}
        <strong>explicit written authorization</strong> to test. Unauthorized
        port scanning may be illegal in your jurisdiction.
      </div>

      {/* Scanner form */}
      <div className="glass-card p-6 space-y-5">
        <h2 className="text-lg font-bold text-white">Network Port Scanner</h2>

        {/* Target */}
        <div>
          <label
            htmlFor="scan-target"
            className="block text-xs font-semibold text-gray-400 mb-1.5 uppercase tracking-wide"
          >
            Target Host / IP
          </label>
          <input
            id="scan-target"
            type="text"
            className={`input-field font-mono ${targetError ? "ring-2 ring-red-500/50" : ""}`}
            placeholder="127.0.0.1 or hostname.local"
            value={target}
            onChange={(e) => {
              setTarget(e.target.value);
              setError(null);
            }}
            autoComplete="off"
            spellCheck={false}
          />
          {targetError && (
            <p className="text-xs text-red-400 mt-1.5">{targetError}</p>
          )}
        </div>

        {/* Ports */}
        <div>
          <label
            htmlFor="scan-ports"
            className="block text-xs font-semibold text-gray-400 mb-1.5 uppercase tracking-wide"
          >
            Ports (comma-separated, max 1024)
          </label>
          <input
            id="scan-ports"
            type="text"
            className={`input-field font-mono ${portError ? "ring-2 ring-red-500/50" : ""}`}
            value={portsStr}
            onChange={(e) => setPortsStr(e.target.value)}
          />
          {portError && (
            <p className="text-xs text-red-400 mt-1.5">{portError}</p>
          )}
          {!portError && (
            <p className="text-xs text-gray-500 mt-1.5">
              {ports.length} port{ports.length !== 1 ? "s" : ""} selected
            </p>
          )}
        </div>

        {/* Authorization checkbox — REQUIRED */}
        <div
          className={`rounded-xl p-4 border transition-all duration-200 ${
            authorized
              ? "bg-emerald-500/10 border-emerald-500/40"
              : "bg-amber-500/5 border-amber-500/30"
          }`}
        >
          <label htmlFor="auth-checkbox" className="flex gap-3 cursor-pointer">
            <div className="pt-0.5">
              <input
                id="auth-checkbox"
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="w-4 h-4 rounded accent-emerald-500 cursor-pointer"
              />
            </div>
            <span className="text-sm text-gray-300 leading-snug">
              I own this target or have{" "}
              <strong className="text-white">
                explicit written authorization
              </strong>{" "}
              to scan it. I understand that unauthorized port scanning may be
              illegal and I accept full legal responsibility for this action.
            </span>
          </label>
        </div>

        {/* Scan button */}
        <div className="flex items-center gap-4">
          <button
            id="scan-btn"
            className="btn-primary"
            onClick={handleScan}
            disabled={!canScan || scanning}
            title={
              !authorized
                ? "You must confirm authorization before scanning"
                : ""
            }
          >
            {scanning ? (
              <span className="flex items-center gap-2">
                <svg
                  className="animate-spin h-4 w-4"
                  viewBox="0 0 24 24"
                  fill="none"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8v8H4z"
                  />
                </svg>
                Scanning…
              </span>
            ) : (
              "🔍 Start Scan"
            )}
          </button>

          {!authorized && (
            <p className="text-xs text-amber-400/70">
              ↑ Check the authorization box to enable scanning
            </p>
          )}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="glass-card p-4 border-l-4 border-red-500 text-red-400 text-sm">
          ✗ {error}
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="glass-card p-6 space-y-5">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white">
              Scan Results — {target}
            </h3>
          </div>
          <ResultsTable results={results} />

          <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center pt-2 border-t border-white/5">
            <button
              id="save-scan-btn"
              className="btn-secondary"
              onClick={handleSaveResult}
              disabled={saving || !lastScanMeta}
            >
              {saving ? "⏳ Saving…" : "💾 Save Results"}
            </button>
            <span className="text-xs text-gray-500">
              Target + open ports + banners are encrypted (AES-256-GCM) before
              storage.
            </span>
          </div>

          {saveMsg && (
            <p
              className={`text-xs font-medium ${saveMsg.ok ? "text-emerald-400" : "text-red-400"}`}
            >
              {saveMsg.ok ? "✓" : "✗"} {saveMsg.text}
            </p>
          )}
        </div>
      )}

      {/* History */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold text-white">Scan History</h3>
          <button
            id="toggle-scan-history"
            className="btn-secondary text-xs py-1.5 px-3"
            onClick={toggleHistory}
          >
            {showHistory ? "Hide" : "Show History"}
          </button>
        </div>
        {showHistory &&
          (histLoading ? (
            <p className="text-gray-500 text-sm text-center py-4">Loading…</p>
          ) : (
            <HistoryTable rows={history} />
          ))}
      </div>
    </div>
  );
}
