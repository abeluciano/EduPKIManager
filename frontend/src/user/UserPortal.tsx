import { Download, RefreshCw, UserRound } from "lucide-react";
import type { CertificateRecord } from "../api/client";

type Props = {
  certificates: CertificateRecord[];
  owner: string;
  onRefresh: () => void;
};

export function UserPortal({ certificates, owner, onRefresh }: Props) {
  function downloadCertificate(certificate: CertificateRecord) {
    const blob = new Blob([certificate.certificate_pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${certificate.common_name}.crt.pem`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="panel">
      <div className="panelHeader">
        <UserRound size={22} />
        <h2>{owner}</h2>
      </div>
      <div className="portalSummary">
        <span>Certificados asignados por el administrador</span>
        <button className="secondary" onClick={onRefresh}>
          <RefreshCw size={16} />
          Actualizar
        </button>
      </div>
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
      {!certificates.length && (
        <div className="emptyState">
          <strong>Sin certificados asignados</strong>
          <span>Cuando el administrador emita certificados para este propietario, apareceran aqui.</span>
        </div>
      )}
    </section>
  );
}
