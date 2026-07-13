import { Download, RefreshCw, UserRound } from "lucide-react";
import type { CertificateRecord } from "../api/client";
import { Pagination, usePagination } from "../components/Pagination";
import { downloadCertificate } from "../utils/certificates";

type Props = {
  certificates: CertificateRecord[];
  owner: string;
  onRefresh: () => void;
};

export function UserPortal({ certificates, owner, onRefresh }: Props) {
  const { currentPage, pageItems, setCurrentPage, totalPages } = usePagination(certificates, 4);

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
          {pageItems.map((certificate) => (
            <div className="auditItem" key={certificate.serial_number}>
              <strong>{certificate.common_name}</strong>
              <span>{certificate.status} / {certificate.certificate_type}</span>
              <small><b>Numero de serie:</b> {certificate.serial_number}</small>
              <button className="secondary" onClick={() => downloadCertificate(certificate)}>
                <Download size={16} />
                Descargar
              </button>
            </div>
          ))}
        </div>
      )}
      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        totalItems={certificates.length}
        onPageChange={setCurrentPage}
      />
      {!certificates.length && (
        <div className="emptyState">
          <strong>Sin certificados asignados</strong>
          <span>Cuando el administrador emita certificados para este propietario, apareceran aqui.</span>
        </div>
      )}
    </section>
  );
}
