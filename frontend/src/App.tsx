import { Activity, FileCheck2, KeyRound, LogIn, LogOut } from "lucide-react";
import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import type { AuthSession, CertificateRecord } from "./api/client";
import { clearStoredSession, getStoredSession, listCertificates, login, setStoredSession } from "./api/client";
import { AdminPanel } from "./admin/AdminPanel";
import { PkiTools } from "./tools/PkiTools";
import { UserPortal } from "./user/UserPortal";

type AppView = "admin" | "user" | "tools";

export function App() {
  const [session, setSession] = useState<AuthSession | undefined>(() => getStoredSession());
  const [certificates, setCertificates] = useState<CertificateRecord[]>([]);
  const [view, setView] = useState<AppView>(session?.role === "admin" ? "admin" : "user");

  async function refresh() {
    if (!session) return;
    setCertificates(await listCertificates());
  }

  useEffect(() => {
    refresh().catch(() => setCertificates([]));
    if (session?.role === "admin" && view === "user") setView("admin");
    if (session?.role === "user" && view === "admin") setView("user");
  }, [session]);

  if (!session) {
    return <LoginScreen onLogin={(nextSession) => { setStoredSession(nextSession); setSession(nextSession); setView(nextSession.role); }} />;
  }

  const active = certificates.filter((item: CertificateRecord) => item.status === "issued").length;
  const revoked = certificates.filter((item: CertificateRecord) => item.status === "revoked").length;
  const isAdmin = session.role === "admin";
  const primaryViewLabel = isAdmin ? "Administracion" : "Mi portal";
  const operationsLabel = isAdmin ? "Operaciones PKI" : "Firmas PDF";

  return (
    <main>
      <header className="topbar">
        <div className="brand">
          <KeyRound size={28} />
          <div>
            <h1>EduPKIManager</h1>
            <span>Consola PKI educativa</span>
          </div>
        </div>
        <div className="segments" role="tablist">
          <button className={(isAdmin ? view === "admin" : view === "user") ? "selected" : ""} onClick={() => setView(isAdmin ? "admin" : "user")}>
            {primaryViewLabel}
          </button>
          <button className={view === "tools" ? "selected" : ""} onClick={() => setView("tools")}>
            {operationsLabel}
          </button>
          <button
            title="Cerrar sesion"
            onClick={() => { clearStoredSession(); setSession(undefined); setCertificates([]); }}
          >
            <LogOut size={16} />
          </button>
        </div>
      </header>

      <section className="metrics">
        <div className="metric">
          <Activity size={20} />
          <span>{certificates.length}</span>
          <small>{isAdmin ? "Total gestionados" : "Mis certificados"}</small>
        </div>
        <div className="metric">
          <FileCheck2 size={20} />
          <span>{active}</span>
          <small>Activos</small>
        </div>
        <div className="metric alert">
          <KeyRound size={20} />
          <span>{revoked}</span>
          <small>Revocados</small>
        </div>
      </section>

      {view === "tools" ? (
        <PkiTools certificates={certificates} role={session.role} />
      ) : isAdmin ? (
        <AdminPanel certificates={certificates} onChanged={refresh} />
      ) : (
        <UserPortal certificates={certificates} owner={session.actor} onRefresh={refresh} />
      )}
    </main>
  );
}

function LoginScreen({ onLogin }: { onLogin: (session: AuthSession) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      onLogin(await login({ username, password }));
    } catch {
      setError("Credenciales invalidas");
    }
  }

  return (
    <main className="loginPage">
      <section className="loginPanel">
        <div className="brand">
          <KeyRound size={30} />
          <div>
            <h1>EduPKIManager</h1>
            <span>Consola PKI educativa</span>
          </div>
        </div>
        <form onSubmit={submit} className="loginForm">
          <label>
            Usuario
            <input value={username} onChange={(event) => setUsername(event.target.value)} />
          </label>
          <label>
            Contrasena
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
          </label>
          {error && <p className="formError">{error}</p>}
          <button className="primary">
            <LogIn size={16} />
            Ingresar
          </button>
        </form>
      </section>
    </main>
  );
}
