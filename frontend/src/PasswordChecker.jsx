/**
 * PasswordChecker.jsx
 *
 * SECURITY INVARIANT: The password string NEVER leaves this component.
 * zxcvbn runs entirely in the browser. Only score + crack_time + timestamp
 * are sent to the backend when the user explicitly clicks "Save to History".
 *
 * Check DevTools → Network while typing: you will see zero requests.
 */

import { useState, useCallback, useEffect } from "react";
import zxcvbn from "zxcvbn";
import axios from "axios";

const API_BASE = (
  import.meta.env.VITE_API_BASE_URL || "https://securescan-api.onrender.com"
).replace(/\/$/, "");
const API = `${API_BASE}/api`;

// Score metadata
const SCORE_META = [
  { label: "Very Weak", color: "bg-red-500", text: "text-red-400", bars: 1 },
  { label: "Weak", color: "bg-orange-500", text: "text-orange-400", bars: 2 },
  { label: "Fair", color: "bg-yellow-500", text: "text-yellow-400", bars: 3 },
  {
    label: "Strong",
    color: "bg-emerald-500",
    text: "text-emerald-400",
    bars: 4,
  },
  {
    label: "Very Strong",
    color: "bg-cyan-500",
    text: "text-cyan-400",
    bars: 5,
  },
];

function StrengthBar({ score }) {
  const meta = SCORE_META[score] ?? SCORE_META[0];
  return (
    <div className="flex gap-1.5 mt-2">
      {[0, 1, 2, 3, 4].map((i) => (
        <div
          key={i}
          className={`h-1.5 flex-1 rounded-full strength-bar-segment ${
            i < meta.bars ? meta.color : "bg-white/10"
          }`}
        />
      ))}
    </div>
  );
}

function FeedbackList({ result }) {
  const suggestions = [];

  if (!result) return null;

  const { password, score, feedback } = result;

  if (password.length < 8) suggestions.push("Use at least 8 characters");
  if (password.length < 12 && password.length >= 8)
    suggestions.push(
      "Longer passwords (12+) are exponentially harder to crack",
    );

  if (feedback.warning) suggestions.push(feedback.warning);
  for (const s of feedback.suggestions) suggestions.push(s);

  // Char-variety hints
  if (!/[A-Z]/.test(password)) suggestions.push("Add uppercase letters");
  if (!/[a-z]/.test(password)) suggestions.push("Add lowercase letters");
  if (!/\d/.test(password)) suggestions.push("Add numbers");
  if (!/[^A-Za-z0-9]/.test(password))
    suggestions.push("Add special characters (!@#$…)");

  if (suggestions.length === 0 && score >= 3)
    return (
      <p className="text-emerald-400 text-xs mt-3">
        ✓ No major weaknesses detected
      </p>
    );

  return (
    <ul className="mt-3 space-y-1">
      {[...new Set(suggestions)].slice(0, 6).map((s, i) => (
        <li key={i} className="text-xs text-yellow-300/80 flex gap-2">
          <span className="shrink-0 text-yellow-500">⚠</span> {s}
        </li>
      ))}
    </ul>
  );
}

function HistoryTable({ rows }) {
  if (!rows.length)
    return (
      <p className="text-gray-500 text-sm text-center py-4">
        No history saved yet.
      </p>
    );

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 text-xs border-b border-white/5">
            <th className="text-left py-2 pr-4 font-medium">#</th>
            <th className="text-left py-2 pr-4 font-medium">Score</th>
            <th className="text-left py-2 pr-4 font-medium">Crack Time</th>
            <th className="text-left py-2 font-medium">Saved At</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const meta = SCORE_META[r.score] ?? SCORE_META[0];
            return (
              <tr key={r.id} className="scan-row border-b border-white/5">
                <td className="py-2 pr-4 text-gray-500">{r.id}</td>
                <td className="py-2 pr-4">
                  <span className={`font-semibold ${meta.text}`}>
                    {meta.label}
                  </span>
                </td>
                <td className="py-2 pr-4 text-gray-300">{r.crack_time}</td>
                <td className="py-2 text-gray-500">
                  {new Date(r.timestamp).toLocaleString()}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function PasswordChecker() {
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [result, setResult] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState(null);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [histLoading, setHistLoading] = useState(false);

  // Client-side analysis — no network request
  const handleChange = useCallback((e) => {
    const val = e.target.value;
    setPassword(val);
    setSaveMsg(null);
    if (val.length === 0) {
      setResult(null);
      return;
    }
    const r = zxcvbn(val);
    setResult(r);
  }, []);

  // POST only score + crack_time + timestamp — NEVER the password
  const handleSave = async () => {
    if (!result) return;
    setSaving(true);
    setSaveMsg(null);
    try {
      const crackTime =
        result.crack_times_display?.offline_slow_hashing_1e4_per_second ??
        "unknown";
      await axios.post(`${API}/password/history`, {
        score: result.score,
        crack_time: crackTime,
        timestamp: new Date().toISOString(),
      });
      setSaveMsg({
        ok: true,
        text: "Metadata saved (score + crack time only).",
      });
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
      const res = await axios.get(`${API}/password/history`);
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

  const meta = result ? (SCORE_META[result.score] ?? SCORE_META[0]) : null;
  const crackTimeDisplay =
    result?.crack_times_display?.offline_slow_hashing_1e4_per_second ?? null;

  return (
    <div className="space-y-6">
      {/* Notice banner */}
      <div className="glass-card p-4 border-l-4 border-indigo-500 text-sm text-gray-300">
        <span className="font-semibold text-indigo-400">
          🔐 Privacy guaranteed:
        </span>{" "}
        Your password is analyzed entirely in this tab using{" "}
        <code className="text-cyan-400 text-xs">zxcvbn</code>. It is never
        transmitted, stored, or logged — not even encrypted.
      </div>

      {/* Checker card */}
      <div className="glass-card p-6">
        <h2 className="text-lg font-bold mb-4 text-white">
          Password Strength Checker
        </h2>

        <div className="relative">
          <input
            id="password-input"
            type={showPw ? "text" : "password"}
            className="input-field pr-12"
            placeholder="Type a password to analyze…"
            value={password}
            onChange={handleChange}
            autoComplete="off"
            spellCheck={false}
          />
          <button
            type="button"
            aria-label={showPw ? "Hide password" : "Show password"}
            onClick={() => setShowPw((p) => !p)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition-colors text-lg"
          >
            {showPw ? "🙈" : "👁️"}
          </button>
        </div>

        {result && (
          <div className="mt-5 space-y-1">
            <div className="flex items-center justify-between">
              <span className={`text-sm font-bold ${meta.text}`}>
                {meta.label}
              </span>
              {crackTimeDisplay && (
                <span className="text-xs text-gray-400">
                  Crack time:{" "}
                  <span className="text-gray-200 font-medium">
                    {crackTimeDisplay}
                  </span>
                </span>
              )}
            </div>
            <StrengthBar score={result.score} />
            <FeedbackList result={result} />
          </div>
        )}

        {result && (
          <div className="mt-6 flex flex-col sm:flex-row gap-3 items-start sm:items-center">
            <button
              id="save-metadata-btn"
              className="btn-primary"
              onClick={handleSave}
              disabled={saving}
            >
              {saving ? "⏳ Saving…" : "💾 Save to History"}
            </button>
            <span className="text-xs text-gray-500">
              Saves: score ({result.score}/4) + crack-time estimate + timestamp
              only.
            </span>
          </div>
        )}

        {saveMsg && (
          <p
            className={`mt-3 text-xs font-medium ${saveMsg.ok ? "text-emerald-400" : "text-red-400"}`}
          >
            {saveMsg.ok ? "✓" : "✗"} {saveMsg.text}
          </p>
        )}
      </div>

      {/* History */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold text-white">Check History</h3>
          <button
            id="toggle-pw-history"
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
