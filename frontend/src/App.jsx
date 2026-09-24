import { useState } from "react";
import PasswordChecker from "./PasswordChecker";
import PortScanner from "./PortScanner";

const TABS = [
  { id: "password", label: "Password Checker", icon: "🔐" },
  { id: "scanner", label: "Port Scanner", icon: "🛡️" },
];

export default function App() {
  const [activeTab, setActiveTab] = useState("password");

  return (
    <div className="min-h-screen bg-gray-950 relative overflow-hidden">
      {/* Ambient background blobs */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-[600px] h-[600px] rounded-full bg-indigo-900/30 blur-3xl" />
        <div className="absolute top-1/2 -right-60 w-[500px] h-[500px] rounded-full bg-violet-900/20 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 w-[400px] h-[400px] rounded-full bg-cyan-900/15 blur-3xl" />
      </div>

      <div className="relative z-10 max-w-4xl mx-auto px-4 py-10">
        {/* Header */}
        <header className="text-center mb-10">
          <div className="inline-flex items-center gap-3 mb-4">
            <span className="text-4xl">🔒</span>
            <h1 className="text-4xl font-extrabold tracking-tight bg-gradient-to-r from-indigo-400 via-violet-400 to-cyan-400 bg-clip-text text-transparent">
              SecureScan
            </h1>
          </div>
          <p className="text-gray-400 text-sm max-w-md mx-auto">
            Security toolkit for developers. All password checks run entirely in
            your browser — nothing is transmitted.
          </p>
          <p className="mt-3 text-sm text-indigo-300 font-medium">
            Developed by Ronodeep Das, Tania Guha Biswas, and Anubhab Sahoo
          </p>
          <div className="mt-2 flex flex-col items-center gap-1 text-xs">
            <a
              href="https://ronodeepdas.github.io/SecureScan/"
              target="_blank"
              rel="noreferrer"
              className="text-cyan-300 hover:text-cyan-200 underline"
            >
              Project live on GitHub Pages
            </a>
            <a
              href="https://github.com/RonodeepDas/SecureScan"
              target="_blank"
              rel="noreferrer"
              className="text-violet-300 hover:text-violet-200 underline"
            >
              GitHub repository
            </a>
          </div>
        </header>

        {/* Tab bar */}
        <nav className="flex gap-2 p-1.5 glass-card mb-8" role="tablist">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              id={`tab-${tab.id}`}
              role="tab"
              aria-selected={activeTab === tab.id}
              aria-controls={`panel-${tab.id}`}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold transition-all duration-200 ${
                activeTab === tab.id
                  ? "bg-indigo-600 text-white shadow-lg shadow-indigo-600/30"
                  : "text-gray-400 hover:text-white hover:bg-white/5"
              }`}
            >
              <span>{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Tab panels */}
        <main>
          <div
            id="panel-password"
            role="tabpanel"
            aria-labelledby="tab-password"
            hidden={activeTab !== "password"}
          >
            {activeTab === "password" && <PasswordChecker />}
          </div>
          <div
            id="panel-scanner"
            role="tabpanel"
            aria-labelledby="tab-scanner"
            hidden={activeTab !== "scanner"}
          >
            {activeTab === "scanner" && <PortScanner />}
          </div>
        </main>

        {/* Footer */}
        <footer className="text-center mt-12 text-gray-600 text-xs">
          SecureScan — local dev only · history endpoints have no auth ·{" "}
          <a
            href="https://ronodeepdas.github.io/SecureScan/"
            className="text-indigo-400 underline"
            target="_blank"
            rel="noreferrer"
          >
            GitHub Pages demo
          </a>{" "}
          ·{" "}
          <a
            href="https://github.com/RonodeepDas/SecureScan"
            className="text-indigo-400 underline"
            target="_blank"
            rel="noreferrer"
          >
            GitHub repo
          </a>{" "}
          · <span className="text-indigo-400">use responsibly</span>
        </footer>
      </div>
    </div>
  );
}
