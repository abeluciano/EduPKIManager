import { Download, RefreshCw, Send } from "lucide-react";
import { useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import type { CertificateRecord } from "../api/client";
import { getCertificate, issueCertificate } from "../api/client";

type Props = {
  certificates: CertificateRecord[];
  issued?: CertificateRecord;
  onIssued: (certificate: CertificateRecord) => void;
};

export function UserPortal({ certificates, issued, onIssued }: Props) {
  const [commonName, setCommonName] = useState("usuario.edu.local");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const certificate = await issueCertificate({
        common_name: commonName,
        certificate_type: "user",
        sans: [commonName],
        validity_days: 365,
      });
      onIssued(certificate);
    } finally {
      setBusy(false);
    }
  }

  function downloadCertificate(certificate: CertificateRecord) {
    const blob = new Blob([certificate.certificate_pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${certificate.common_name}.crt.pem`;
    link.click();
    URL.revokeObjectURL(url);
  }

  async function refreshStatus() {
    if (!issued) return;
    onIssued(await getCertificate(issued.id));
  }

  return (
    <section className="panel">
      <div className="panelHeader">
        <Send size={22} />
        <h2>Usuario final</h2>
      </div>
      <form onSubmit={submit} className="requestForm">
        <label>
          Nombre comun
          <input value={commonName} onChange={(event: ChangeEvent<HTMLInputElement>) => setCommonName(event.target.value)} />
        </label>
        <label>
          Tipo
          <input value="Usuario" readOnly />
        </label>
        <button className="primary" disabled={busy}>
          <Send size={16} />
          Emitir
        </button>
      </form>
      {issued && (
        <div className="issuedCert">
          <div>
            <strong>{issued.common_name}</strong>
            <span>{issued.serial_number}</span>
          </div>
          <button title="Descargar certificado" onClick={() => downloadCertificate(issued)}>
            <Download size={16} />
          </button>
          <button title="Actualizar estado" onClick={refreshStatus}>
            <RefreshCw size={16} />
          </button>
        </div>
      )}
      {certificates.length > 0 && (
        <div className="auditList">
          {certificates.map((certificate) => (
            <div className="auditItem" key={certificate.serial_number}>
              <strong>{certificate.common_name}</strong>
              <span>{certificate.status} / {certificate.certificate_type}</span>
              <small>{certificate.serial_number}</small>
              <button className="secondary" onClick={() => downloadCertificate(certificate)}>
                <Download size={16} />
                Descargar
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
