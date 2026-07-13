import { Ban, CirclePause, Download, Eye, RefreshCw, Send, ShieldCheck } from "lucide-react";
import { Fragment, useState } from "react";
import type { FormEvent } from "react";
import type { CertificateRecord } from "../api/client";
import { OWNER_ACCOUNTS, certificateAction, issueCertificate } from "../api/client";
import { Pagination, usePagination } from "../components/Pagination";
import { downloadCertificate } from "../utils/certificates";

type Props = {
  certificates: CertificateRecord[];
  onChanged: () => void;
};

export function AdminPanel({ certificates, onChanged }: Props) {
  const [commonName, setCommonName] = useState("portal.edu.local");
  const [type, setType] = useState("server");
  const [owner, setOwner] = useState<string>(OWNER_ACCOUNTS[0].displayName);
  const [busy, setBusy] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const { currentPage, pageItems, setCurrentPage, totalPages } = usePagination(certificates, 8);

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
            {pageItems.map((item) => (
              <Fragment key={item.id}>
                <tr>
                  <td>{item.common_name}</td>
                  <td>{item.owner}</td>
                  <td>{item.certificate_type}</td>
                  <td><span className={`status ${item.status}`}>{item.status}</span></td>
                  <td>{new Date(item.not_after).toLocaleDateString()}</td>
                  <td className="actions">
                    <button
                      type="button"
                      title="Ver detalles"
                      aria-label={`Ver detalles de ${item.common_name}`}
                      aria-expanded={expandedId === item.id}
                      onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}
                    ><Eye size={16} /></button>
                    <button
                      type="button"
                      title="Descargar certificado"
                      aria-label={`Descargar certificado ${item.common_name}`}
                      onClick={() => downloadCertificate(item)}
                    ><Download size={16} /></button>
                    <button type="button" title="Renovar" aria-label={`Renovar ${item.common_name}`} onClick={() => runAction(item.id, "renew")}><RefreshCw size={16} /></button>
                    <button type="button" title="Suspender" aria-label={`Suspender ${item.common_name}`} onClick={() => runAction(item.id, "suspend")}><CirclePause size={16} /></button>
                    <button type="button" title="Revocar" aria-label={`Revocar ${item.common_name}`} onClick={() => runAction(item.id, "revoke")}><Ban size={16} /></button>
                  </td>
                </tr>
                {expandedId === item.id && (
                  <tr className="certificateDetailsRow">
                    <td colSpan={6}>
                      <dl className="certificateDetails">
                        <div>
                          <dt>Numero de serie</dt>
                          <dd>{item.serial_number}</dd>
                        </div>
                        <div>
                          <dt>Huella SHA-256</dt>
                          <dd>{item.fingerprint_sha256}</dd>
                        </div>
                        <div>
                          <dt>Valido hasta</dt>
                          <dd>{new Date(item.not_after).toLocaleString()}</dd>
                        </div>
                      </dl>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        totalItems={certificates.length}
        onPageChange={(page) => {
          setExpandedId(null);
          setCurrentPage(page);
        }}
      />
    </section>
  );
}
