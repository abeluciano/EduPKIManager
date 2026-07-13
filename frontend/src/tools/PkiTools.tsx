import { Download, FileCheck2, FileSignature, ListChecks, Radio, Search, ShieldCheck, Wifi } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import type { AuditLogResponse, CertificateRecord, CrlManifest, OcspResponse, PadesSignResponse, PadesVerifyResponse, PdfSignatureEnvelope, PdfVerification, TlsDemoResponse, TrustPurpose, TrustReport } from "../api/client";
import { apiUrl, checkOcsp, getAuditLog, getCrlManifest, getRootCa, runTlsDemo, signPdf, signPdfEmbedded, validateCertificateTrust, verifyPdf, verifyPdfEmbedded } from "../api/client";

type Props = {
  certificates: CertificateRecord[];
  role: "admin" | "user";
};

export function PkiTools({ certificates, role }: Props) {
  const availableCertificates = useMemo(() => {
    const bySerial = new Map(certificates.map((item) => [item.serial_number, item]));
    return [...bySerial.values()];
  }, [certificates]);

  const defaultSerial = availableCertificates[0]?.serial_number ?? "";
  const [serialNumber, setSerialNumber] = useState(defaultSerial);
  const [pdfBase64, setPdfBase64] = useState("");
  const [signatureText, setSignatureText] = useState("");
  const [signatureEnvelope, setSignatureEnvelope] = useState<PdfSignatureEnvelope>();
  const [verification, setVerification] = useState<PdfVerification>();
  const [trustPurpose, setTrustPurpose] = useState<TrustPurpose>("document_signing");
  const [trustReport, setTrustReport] = useState<TrustReport>();
  const [padesSignature, setPadesSignature] = useState<PadesSignResponse>();
  const [padesVerification, setPadesVerification] = useState<PadesVerifyResponse>();
  const [ocsp, setOcsp] = useState<OcspResponse>();
  const [rootCa, setRootCa] = useState("");
  const [audit, setAudit] = useState<AuditLogResponse>();
  const [tls, setTls] = useState<TlsDemoResponse>();
  const [crlManifest, setCrlManifest] = useState<CrlManifest>();
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!serialNumber && defaultSerial) setSerialNumber(defaultSerial);
  }, [defaultSerial, serialNumber]);

  useEffect(() => {
    const selected = availableCertificates.find((item) => item.serial_number === serialNumber);
    if (selected) setTrustPurpose(defaultPurpose(selected));
  }, [availableCertificates, serialNumber]);

  async function loadPdf(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setPdfBase64(await fileToBase64(file));
    setMessage(file.name);
  }

  async function loadSignature(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setSignatureText(text);
      setSignatureEnvelope(JSON.parse(text) as PdfSignatureEnvelope);
      setMessage(file.name);
    } catch {
      setMessage("Firma JSON invalida");
    }
  }

  async function submitSign(event: FormEvent) {
    event.preventDefault();
    try {
      const envelope = await signPdf({ serial_number: serialNumber, pdf_base64: pdfBase64 });
      setSignatureEnvelope(envelope);
      setSignatureText(JSON.stringify(envelope, null, 2));
      setVerification(undefined);
      setMessage("PDF firmado");
    } catch (error) {
      setMessage(readError(error));
    }
  }

  async function submitVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const envelope = (signatureEnvelope ?? JSON.parse(signatureText)) as PdfSignatureEnvelope;
      const response = await verifyPdf({ pdf_base64: pdfBase64, signature_envelope: envelope });
      setVerification(response);
      if (response.trust_report) setTrustReport(response.trust_report);
      setMessage("Firma verificada");
    } catch (error) {
      setMessage(readError(error));
    }
  }

  async function submitPadesSign() {
    try {
      const response = await signPdfEmbedded({ serial_number: serialNumber, pdf_base64: pdfBase64 });
      setPadesSignature(response);
      setMessage("PDF PAdES firmado");
    } catch (error) {
      setMessage(readError(error));
    }
  }

  async function submitPadesVerify() {
    try {
      setPadesVerification(await verifyPdfEmbedded({ signed_pdf_base64: pdfBase64 }));
      setMessage("PDF PAdES verificado");
    } catch (error) {
      setMessage(readError(error));
    }
  }

  async function runOcsp(event: FormEvent) {
    event.preventDefault();
    try {
      setOcsp(await checkOcsp(serialNumber));
    } catch (error) {
      setMessage(readError(error));
    }
  }

  async function runTrustValidation(event: FormEvent) {
    event.preventDefault();
    try {
      setTrustReport(await validateCertificateTrust({ serial_number: serialNumber, purpose: trustPurpose }));
      setMessage("Confianza evaluada");
    } catch (error) {
      setMessage(readError(error));
    }
  }

  async function loadRootCa() {
    try {
      const response = await getRootCa();
      const root = response.root_certificate_pem ?? response.certificate_pem;
      setRootCa(root);
      downloadText("edupki-root-ca.pem", root);
    } catch (error) {
      setMessage(readError(error));
    }
  }

  async function loadAudit() {
    try {
      setAudit(await getAuditLog());
    } catch (error) {
      setMessage(readError(error));
    }
  }

  async function loadCrlManifest() {
    try {
      setCrlManifest(await getCrlManifest());
    } catch (error) {
      setMessage(readError(error));
    }
  }

  async function runTls() {
    try {
      setTls(await runTlsDemo());
    } catch (error) {
      setMessage(readError(error));
    }
  }

  return (
    <div className={`toolGrid ${role === "admin" ? "adminTools" : "userTools"}`}>
      {message && <div className="toolMessage widePanel">{message}</div>}
      <section className="panel toolPanel signPanel">
        <div className="panelHeader">
          <FileSignature size={22} />
          <h2>Firma PDF</h2>
        </div>
        <form className="stackForm" onSubmit={submitSign}>
          <label>
            Certificado
            <select value={serialNumber} onChange={(event) => setSerialNumber(event.target.value)}>
              {availableCertificates.map((item) => (
                <option key={item.serial_number} value={item.serial_number}>
                  {item.common_name} - {item.status}
                </option>
              ))}
              {!availableCertificates.length && <option value="">Sin certificados</option>}
            </select>
          </label>
          <label>
            PDF
            <input type="file" accept="application/pdf" onChange={loadPdf} />
          </label>
          <button className="primary" disabled={!serialNumber || !pdfBase64}>
            <FileSignature size={16} />
            Firmar JSON
          </button>
          <button className="secondary" type="button" disabled={!serialNumber || !pdfBase64} onClick={submitPadesSign}>
            <FileSignature size={16} />
            Firmar PAdES
          </button>
        </form>
        {padesSignature && (
          <div className="resultLine">
            <strong>{padesSignature.format}</strong>
            <span>{padesSignature.signed_pdf_sha256}</span>
            <button className="secondary" onClick={() => downloadBase64("documento-firmado-pades.pdf", padesSignature.signed_pdf_base64, "application/pdf")}>
              <Download size={16} />
              PDF firmado
            </button>
          </div>
        )}
        {signatureText && (
          <div className="resultBox">
            <div className="resultActions">
              <strong>Sobre de firma</strong>
              <button title="Descargar firma" onClick={() => downloadText("firma-edupki.json", signatureText)}>
                <Download size={16} />
              </button>
            </div>
            <textarea value={signatureText} onChange={(event) => setSignatureText(event.target.value)} />
          </div>
        )}
      </section>

      <section className="panel toolPanel verifyPanel">
        <div className="panelHeader">
          <FileCheck2 size={22} />
          <h2>Verificacion PDF</h2>
        </div>
        <form className="stackForm" onSubmit={submitVerify}>
          <label>
            PDF original o PDF firmado
            <input type="file" accept="application/pdf" onChange={loadPdf} />
          </label>
          <label>
            Firma JSON
            <input type="file" accept="application/json" onChange={loadSignature} />
          </label>
          <button className="primary" disabled={!pdfBase64 || !signatureText}>
            <FileCheck2 size={16} />
            Verificar JSON
          </button>
          <button className="secondary" type="button" disabled={!pdfBase64} onClick={submitPadesVerify}>
            <FileCheck2 size={16} />
            Verificar PAdES
          </button>
        </form>
        {padesVerification && (
          <div className={`verification ${padesVerification.valid ? "ok" : "bad"}`}>
            <strong>{padesVerification.valid ? "PAdES valido" : "PAdES no valido"}</strong>
            <span>Firmas: {padesVerification.signature_count}</span>
            <span>{padesVerification.signatures[0]?.summary ?? "Sin detalles"}</span>
          </div>
        )}
        {verification && (
          <div className={`verification ${verification.valid ? "ok" : "bad"}`}>
            <strong>{verification.valid ? "Firma valida" : "Firma no valida"}</strong>
            <span>Documento: {String(verification.valid_digest)}</span>
            <span>Firma: {String(verification.valid_signature)}</span>
            <span>Cadena: {String(verification.valid_chain)}</span>
            <span>Confianza: {String(verification.valid_trust ?? verification.trust_report?.valid ?? false)}</span>
          </div>
        )}
      </section>

      {role === "admin" && (
        <section className="panel toolPanel trustPanel">
          <div className="panelHeader">
            <ShieldCheck size={22} />
            <h2>Confianza X.509</h2>
          </div>
          <form className="stackForm" onSubmit={runTrustValidation}>
            <label>
              Certificado
              <select value={serialNumber} onChange={(event) => setSerialNumber(event.target.value)}>
                {availableCertificates.map((item) => (
                  <option key={item.serial_number} value={item.serial_number}>
                    {item.common_name} - {item.status}
                  </option>
                ))}
                {!availableCertificates.length && <option value="">Sin certificados</option>}
              </select>
            </label>
            <label>
              Proposito
              <select value={trustPurpose} onChange={(event) => setTrustPurpose(event.target.value as TrustPurpose)}>
                <option value="document_signing">Firma documental</option>
                <option value="server_auth">Servidor TLS</option>
                <option value="client_auth">Cliente</option>
                <option value="device_auth">Dispositivo</option>
                <option value="any">General</option>
              </select>
            </label>
            <button className="primary" disabled={!serialNumber}>
              <ShieldCheck size={16} />
              Validar
            </button>
          </form>
          {trustReport && (
            <div className={`verification ${trustReport.valid ? "ok" : "bad"}`}>
              <strong>{trustReport.valid ? "Confianza valida" : "Confianza no valida"}</strong>
              <span>Cadena: {String(trustReport.chain.valid)}</span>
              <span>Vigencia: {String(trustReport.validity.valid)}</span>
              <span>Uso: {String(trustReport.key_usage.valid && trustReport.extended_key_usage.valid)}</span>
              <span>Revocacion: {trustReport.revocation.status}</span>
              {trustReport.errors.slice(0, 4).map((item) => (
                <small key={item}>{item}</small>
              ))}
            </div>
          )}
        </section>
      )}

      {role === "admin" && (
        <section className="panel toolPanel ocspPanel">
          <div className="panelHeader">
            <Radio size={22} />
            <h2>OCSP</h2>
          </div>
          <form className="stackForm" onSubmit={runOcsp}>
            <label>
              Numero de serie
              <input value={serialNumber} onChange={(event) => setSerialNumber(event.target.value)} />
            </label>
            <button className="primary">
              <Search size={16} />
              Consultar
            </button>
          </form>
          {ocsp && (
            <div className="resultLine">
              <strong>{ocsp.status}</strong>
              {ocsp.details && <span>{ocsp.details.certificate_status} / {ocsp.details.hash_algorithm}</span>}
            </div>
          )}
        </section>
      )}

      {role === "admin" && (
        <section className="panel toolPanel caPanel">
          <div className="panelHeader">
            <ShieldCheck size={22} />
            <h2>CA y CRL</h2>
          </div>
          <div className="buttonRow">
            <button className="secondary" onClick={loadRootCa}>
              <Download size={16} />
              Root CA
            </button>
            <a className="secondary" href={apiUrl("/crl.pem")} download="edupki.crl.pem">
              <Download size={16} />
              CRL PEM
            </a>
            <a className="secondary" href={apiUrl("/crl.der")} download="edupki.crl.der">
              <Download size={16} />
              CRL DER
            </a>
            <button className="secondary" onClick={loadCrlManifest}>
              <ListChecks size={16} />
              Versiones
            </button>
          </div>
          {rootCa && <textarea className="smallTextArea" value={rootCa} readOnly />}
          {crlManifest && (
            <div className="auditList">
              <div className="resultLine">
                <strong>CRL actual #{crlManifest.current_number}</strong>
                <span>{crlManifest.versions[crlManifest.versions.length - 1]?.revoked_count ?? 0} certificados revocados/suspendidos</span>
              </div>
              {crlManifest.versions.slice(-5).reverse().map((version) => (
                <div className="auditItem" key={version.number}>
                  <strong>Version {version.number}</strong>
                  <span>{version.revoked_count} entradas</span>
                  <small>{new Date(version.created_at).toLocaleString()}</small>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {role === "admin" && (
        <section className="panel toolPanel tlsPanel">
          <div className="panelHeader">
            <Wifi size={22} />
            <h2>TLS 1.3</h2>
          </div>
          <button className="primary" onClick={runTls}>
            <ShieldCheck size={16} />
            Probar handshake
          </button>
          {tls && (
            <div className="resultLine">
              <strong>{tls.client_tls_version}</strong>
              {tls.hostname && <span>Host: {tls.hostname}</span>}
              <span>Servidor: {tls.server_tls_version}</span>
              <span>Respuesta: {tls.server_reply}</span>
            </div>
          )}
        </section>
      )}

      {role === "admin" && (
        <section className="panel toolPanel auditPanel">
          <div className="panelHeader">
            <ListChecks size={22} />
            <h2>Auditoria</h2>
          </div>
          <button className="primary" onClick={loadAudit}>
            <Search size={16} />
            Cargar
          </button>
          {audit && (
            <div className="auditList">
              <div className={`verification ${audit.valid_chain ? "ok" : "bad"}`}>
                <strong>Cadena {audit.valid_chain ? "integra" : "alterada"}</strong>
                <span>Entradas: {audit.verification.entry_count}</span>
                {audit.verification.last_hash && <span>Ultimo hash: {audit.verification.last_hash.slice(0, 16)}...</span>}
                {audit.verification.broken_at_index && <span>Ruptura: linea {audit.verification.broken_at_index}</span>}
                {audit.verification.errors.slice(0, 3).map((item) => (
                  <small key={item}>{item}</small>
                ))}
              </div>
              {audit.entries.map((entry) => (
                <div className="auditItem" key={entry.entry_hash}>
                  <strong>{entry.sequence_number ? `#${entry.sequence_number} ${entry.operation}` : entry.operation}</strong>
                  <span>{entry.actor} / {entry.result}</span>
                  <span>{entry.entry_hash.slice(0, 16)}...</span>
                  <small>{new Date(entry.timestamp).toLocaleString()}</small>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

async function fileToBase64(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  let binary = "";
  const bytes = new Uint8Array(buffer);
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return window.btoa(binary);
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function downloadBase64(filename: string, contentBase64: string, mimeType: string) {
  const binary = window.atob(contentBase64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  const blob = new Blob([bytes], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function readError(error: unknown) {
  return error instanceof Error ? error.message : "Operacion fallida";
}

function defaultPurpose(certificate: CertificateRecord): TrustPurpose {
  if (certificate.certificate_type === "server") return "server_auth";
  if (certificate.certificate_type === "device") return "device_auth";
  return "document_signing";
}
