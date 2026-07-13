export type CertificateRecord = {
  id: number;
  serial_number: string;
  common_name: string;
  certificate_type: "user" | "server" | "device";
  owner: string;
  status: "issued" | "suspended" | "revoked" | "renewed";
  certificate_pem: string;
  private_key_pem?: string;
  fingerprint_sha256: string;
  not_after: string;
};

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly detail: string,
  ) {
    super(detail);
    this.name = "ApiError";
  }
}

export type AuthSession = {
  actor: string;
  display_name: string;
  role: "admin" | "user";
  token: string;
  username: string;
};

export const OWNER_ACCOUNTS = [
  { username: "lasalle", displayName: "Universidad la Salle" },
  { username: "abel.aragon", displayName: "Abel Aragon" },
  { username: "carlos.mijail", displayName: "Carlos Mijail" },
  { username: "josshua.flores", displayName: "Josshua Flores" },
  { username: "marco.alatrista", displayName: "Marco Alatrista" },
] as const;

export type RootCaResponse = {
  certificate_pem: string;
  root_certificate_pem?: string;
  intermediate_certificate_pem?: string;
  certificate_chain_pem?: string;
};

export type OcspResponse = {
  status: "good" | "revoked" | "unknown";
  ocsp_der_base64?: string;
  details?: {
    response_status: string;
    certificate_status: string;
    serial_number: string;
    hash_algorithm: string;
  };
};

export type PdfSignatureEnvelope = {
  format: string;
  actor: string;
  signed_at: string;
  document_sha256: string;
  certificate_serial_number: string;
  certificate_fingerprint_sha256: string;
  certificate_pem: string;
  issuer_certificate_pem?: string;
  ca_certificate_pem: string;
  signature_base64: string;
  signature_algorithm: string;
};

export type PdfVerification = {
  valid: boolean;
  valid_digest: boolean;
  valid_signature: boolean;
  valid_chain: boolean;
  detached_signature_valid?: boolean;
  valid_trust?: boolean;
  certificate_serial_number: string;
  chain_trust_anchor: string;
  trust_report?: TrustReport;
};

export type TrustPurpose = "document_signing" | "server_auth" | "client_auth" | "device_auth" | "any";

export type TrustReport = {
  valid: boolean;
  purpose: TrustPurpose;
  checked_at: string;
  certificate: {
    serial_number: string;
    subject: string;
    issuer: string;
    fingerprint_sha256: string;
    not_before: string;
    not_after: string;
  };
  chain: { valid: boolean; trust_anchor: string; errors: string[] };
  validity: { valid: boolean; errors: string[] };
  basic_constraints: { valid: boolean; ca: boolean | null; errors: string[] };
  key_usage: { valid: boolean; errors: string[] };
  extended_key_usage: { valid: boolean; names: string[]; errors: string[] };
  certificate_policies: { valid: boolean; oids: string[]; errors: string[] };
  revocation: {
    valid: boolean;
    status: "good" | "revoked" | "unknown";
    local_status?: string;
    revoked_by_database: boolean;
    revoked_by_crl: boolean;
    ocsp: { checked: boolean; status?: string; signature_valid?: boolean; errors: string[] };
    errors: string[];
  };
  errors: string[];
};

export type PadesSignResponse = {
  format: "PAdES-B-B";
  field_name: string;
  subfilter: string;
  signed_pdf_sha256: string;
  signed_pdf_base64: string;
};

export type PadesVerifyResponse = {
  valid: boolean;
  signature_count: number;
  signed_pdf_sha256: string;
  signatures: Array<{
    field_name: string;
    valid: boolean;
    trusted: boolean;
    intact: boolean;
    summary: string;
  }>;
};

export type AuditEntry = {
  schema_version?: number;
  sequence_number?: number;
  timestamp: string;
  operation: string;
  actor: string;
  result: string;
  details: Record<string, unknown>;
  previous_hash: string;
  entry_hash: string;
};

export type AuditLogResponse = {
  valid_chain: boolean;
  verification: {
    entry_count: number;
    first_hash: string | null;
    last_hash: string | null;
    broken_at_index: number | null;
    errors: string[];
  };
  entries: AuditEntry[];
};

export type TlsDemoResponse = {
  hostname?: string;
  client_tls_version: string;
  server_tls_version: string;
  server_reply: string;
};

export type CrlManifest = {
  current_number: number;
  latest_pem?: string;
  latest_der?: string;
  versions: Array<{
    number: number;
    created_at: string;
    last_update: string;
    next_update: string | null;
    revoked_count: number;
    pem_path: string;
    der_path: string;
    pem_sha256: string;
    der_sha256: string;
    crl_number: number;
  }>;
};

const baseUrl = import.meta.env.VITE_API_URL ?? "/api";
const storageKey = "edupki_auth";

export function apiUrl(path: string) {
  return `${baseUrl}${path}`;
}

export function getStoredSession(): AuthSession | undefined {
  if (typeof window === "undefined") return undefined;
  const raw = window.localStorage.getItem(storageKey);
  return raw ? JSON.parse(raw) as AuthSession : undefined;
}

export function setStoredSession(session: AuthSession) {
  window.localStorage.setItem(storageKey, JSON.stringify(session));
}

export function clearStoredSession() {
  window.localStorage.removeItem(storageKey);
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const session = getStoredSession();
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(session ? { Authorization: `Bearer ${session.token}`, "X-Actor": session.actor } : {}),
      ...(options.headers ?? {}),
    },
  });
  if (!response.ok) {
    let code = "request_failed";
    let detail = defaultErrorMessage(response.status);
    if (response.headers.get("content-type")?.includes("application/json")) {
      try {
        const payload = await response.json() as { code?: unknown; detail?: unknown };
        if (typeof payload.code === "string") code = payload.code;
        if (typeof payload.detail === "string" && payload.detail.length <= 300) detail = payload.detail;
      } catch {
        // The status-based message remains intentionally free of server internals.
      }
    }
    if (response.status === 413) {
      code = "pdf_too_large";
      detail = "El PDF supera el limite de 10 MB.";
    }
    throw new ApiError(response.status, code, detail);
  }
  return response.json() as Promise<T>;
}

function defaultErrorMessage(status: number) {
  if (status === 400) return "La solicitud no se pudo procesar. Revisa los datos seleccionados.";
  if (status === 401) return "Tu sesion vencio. Vuelve a iniciar sesion.";
  if (status === 403) return "No tienes permiso para realizar esta operacion.";
  if (status === 404) return "No se encontro el recurso solicitado.";
  if (status >= 500) return "El servicio no pudo completar la operacion. Intenta nuevamente.";
  return "No se pudo completar la operacion.";
}

export function login(payload: { username: string; password: string }) {
  return request<AuthSession>("/auth/login/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function listCertificates() {
  return request<CertificateRecord[]>("/certificates/");
}

export function getCertificate(id: number) {
  return request<CertificateRecord>(`/certificates/${id}/`);
}

export function issueCertificate(payload: {
  common_name: string;
  certificate_type: string;
  owner?: string;
  sans: string[];
  validity_days: number;
}) {
  return request<CertificateRecord>("/certificates/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function certificateAction(id: number, action: "revoke" | "suspend" | "renew") {
  return request<CertificateRecord>(`/certificates/${id}/${action}/`, {
    method: "POST",
    body: JSON.stringify(action === "revoke" ? { reason: "key_compromise" } : {}),
  });
}

export function getRootCa() {
  return request<RootCaResponse>("/ca/root/");
}

export function checkOcsp(serialNumber: string) {
  return request<OcspResponse>("/ocsp/status/", {
    method: "POST",
    body: JSON.stringify({ serial_number: serialNumber }),
  });
}

export function validateCertificateTrust(payload: { serial_number?: string; certificate_pem?: string; purpose: TrustPurpose }) {
  return request<TrustReport>("/certificates/validate/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function signPdf(payload: { serial_number: string; pdf_base64: string }) {
  return request<PdfSignatureEnvelope>("/pdf/sign/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function verifyPdf(payload: { pdf_base64: string; signature_envelope: PdfSignatureEnvelope }) {
  return request<PdfVerification>("/pdf/verify/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function signPdfEmbedded(payload: { serial_number: string; pdf_base64: string }) {
  return request<PadesSignResponse>("/pdf/sign-embedded/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function verifyPdfEmbedded(payload: { signed_pdf_base64: string }) {
  return request<PadesVerifyResponse>("/pdf/verify-embedded/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getAuditLog() {
  return request<AuditLogResponse>("/audit/");
}

export function runTlsDemo() {
  return request<TlsDemoResponse>("/tls/demo/");
}

export function getCrlManifest() {
  return request<CrlManifest>("/crl/manifest/");
}
