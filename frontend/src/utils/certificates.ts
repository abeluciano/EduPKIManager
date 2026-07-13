import type { CertificateRecord } from "../api/client";

export function downloadCertificate(certificate: CertificateRecord) {
  const blob = new Blob([certificate.certificate_pem], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${certificate.common_name}.crt.pem`;
  link.click();
  URL.revokeObjectURL(url);
}
