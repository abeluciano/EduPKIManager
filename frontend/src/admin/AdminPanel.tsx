import { Ban, CirclePause, RefreshCw, Send, ShieldCheck } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";
import type { CertificateRecord } from "../api/client";
import { OWNER_ACCOUNTS, certificateAction, issueCertificate } from "../api/client";

type Props = {
  certificates: CertificateRecord[];
  onChanged: () => void;
};

export function AdminPanel({ certificates, onChanged }: Props) {
  const [commonName, setCommonName] = useState("portal.edu.local");
  const [type, setType] = useState("server");
  const [owner, setOwner] = useState<string>(OWNER_ACCOUNTS[0].displayName);
  const [busy, setBusy] = useState(false);

  async function runAction(id: number, action: "revoke" | "suspend" | "renew") {
    await certificateAction(id, action);
    onChanged();
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await issueCertificate({
        common_name: commonName,
        certificate_type: type,
        owner,
        sans: [commonName],
        validity_days: 365,
      });
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <div className="panelHeader">
        <ShieldCheck size={22} />
        <h2>Administrador</h2>
      </div>
      <form onSubmit={submit} className="requestForm adminIssue">
        <label>
          Nombre comun
          <input value={commonName} onChange={(event) => setCommonName(event.target.value)} />
        </label>
        <label>
          Tipo
          <select value={type} onChange={(event) => setType(event.target.value)}>
            <option value="user">Usuario</option>
            <option value="server">Servidor</option>
            <option value="device">Dispositivo</option>
          </select>
        </label>
        <label>
          Propietario
          <select value={owner} onChange={(event) => setOwner(event.target.value)}>
            {OWNER_ACCOUNTS.map((account) => (
              <option key={account.username} value={account.displayName}>
                {account.displayName}
              </option>
            ))}
          </select>
        </label>
        <button className="primary" disabled={busy}>
          <Send size={16} />
          Emitir
        </button>
      </form>
      <div className="tableWrap">
        <table>
          <thead>
            <tr>
              <th>CN</th>
              <th>Propietario</th>
              <th>Tipo</th>
              <th>Estado</th>
              <th>Vence</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {certificates.map((item) => (
              <tr key={item.id}>
                <td>{item.common_name}</td>
                <td>{item.owner}</td>
                <td>{item.certificate_type}</td>
                <td><span className={`status ${item.status}`}>{item.status}</span></td>
                <td>{new Date(item.not_after).toLocaleDateString()}</td>
                <td className="actions">
                  <button title="Renovar" onClick={() => runAction(item.id, "renew")}><RefreshCw size={16} /></button>
                  <button title="Suspender" onClick={() => runAction(item.id, "suspend")}><CirclePause size={16} /></button>
                  <button title="Revocar" onClick={() => runAction(item.id, "revoke")}><Ban size={16} /></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
