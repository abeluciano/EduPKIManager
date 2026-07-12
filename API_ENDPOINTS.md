# Documentacion de Endpoints - EduPKIManager

Base URL local:

```text
https://edupkimanager.com/api
```

Base URL directa de respaldo:

```text
http://127.0.0.1:8000/api
```

Header opcional para auditoria:

```http
X-Actor: admin
```

Si no se envia `X-Actor`, el backend registra el actor como `anonymous`, salvo que exista un usuario Django autenticado.

Header de autenticacion:

```http
Authorization: Bearer <token>
```

El token se obtiene con `POST /auth/login/`.

## Modelo de Certificado

Respuesta comun de certificado:

```json
{
  "id": 1,
  "serial_number": "123456789",
  "common_name": "portal.edu.local",
  "certificate_type": "server",
  "owner": "admin",
  "status": "issued",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "fingerprint_sha256": "abc123...",
  "not_before": "2026-06-24T23:00:00Z",
  "not_after": "2027-06-24T23:00:00Z",
  "revoked_at": null,
  "revocation_reason": ""
}
```

Valores permitidos:

- `certificate_type`: `user`, `server`, `device`
- `status`: `issued`, `suspended`, `revoked`, `renewed`
- `key_algorithm`: `rsa-2048`, `rsa-4096`, `ecdsa`, `ecdsa-p256`, `p-256`

## Health Check

### `GET /health/`

Verifica que la API este levantada.

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/health/
```

Respuesta `200`:

```json
{
  "status": "ok",
  "service": "EduPKIManager"
}
```

### `GET /readiness/`

Verifica que el despliegue este listo para operar: conexion a base de datos, Root/Intermediate CA, publicacion CRL y cadena de auditoria.

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/readiness/
```

Respuesta `200`:

```json
{
  "status": "ready",
  "checks": {
    "database": { "ready": true },
    "ca": {
      "ready": true,
      "root_pem_bytes": 1800,
      "intermediate_pem_bytes": 1800
    },
    "crl": {
      "ready": true,
      "current_number": 1,
      "versions": 1
    },
    "audit": {
      "ready": true,
      "entry_count": 30,
      "last_hash": "abc123...",
      "errors": []
    }
  }
}
```

Si algun chequeo falla, responde `503` con `status: "not_ready"` y el detalle del componente afectado.

## Autenticacion

### `POST /auth/login/`

Autentica un usuario demo y devuelve un token firmado para las operaciones protegidas.

Usuarios demo:

- `admin` / `admin123`, rol `admin`
- `user` / `user123`, rol `user`

Body:

```json
{
  "username": "admin",
  "password": "admin123"
}
```

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

Respuesta `200`:

```json
{
  "actor": "admin",
  "role": "admin",
  "token": "eyJ..."
}
```

## Root CA

### `GET /ca/root/`

Devuelve el certificado PEM de la CA raiz. Si aun no existe, el backend lo genera automaticamente.
Tambien devuelve la Intermediate CA y la cadena completa.

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/ca/root/
```

Respuesta `200`:

```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "root_certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "intermediate_certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "certificate_chain_pem": "-----BEGIN CERTIFICATE-----..."
}
```

### `GET /ca/root.pem`

Descarga directa de la Root CA en PEM. Es el certificado que se debe importar como autoridad de confianza para que el navegador confie en `https://edupkimanager.com`.

Ejemplo:

```bash
curl -o edupki-root-ca.pem http://127.0.0.1:8000/api/ca/root.pem
```

Respuesta `200`:

```text
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

### `GET /ca/chain.pem`

Descarga la cadena publica Intermediate CA + Root CA en PEM.

Ejemplo:

```bash
curl -o edupki-ca-chain.pem http://127.0.0.1:8000/api/ca/chain.pem
```

## Certificados

### `GET /certificates/`

Lista certificados registrados. No incluye la clave privada.

Requiere rol `admin` o `user`.

- `admin`: recibe todos los certificados.
- `user`: recibe solo certificados cuyo `owner` coincide con el actor autenticado.

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/certificates/ \
  -H "Authorization: Bearer <admin_token>"
```

Respuesta `200`:

```json
[
  {
    "id": 1,
    "serial_number": "123456789",
    "common_name": "portal.edu.local",
    "certificate_type": "server",
    "owner": "admin",
    "status": "issued",
    "certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "fingerprint_sha256": "abc123...",
    "not_before": "2026-06-24T23:00:00Z",
    "not_after": "2027-06-24T23:00:00Z",
    "revoked_at": null,
    "revocation_reason": ""
  }
]
```

### `POST /certificates/`

Emite un nuevo certificado X.509 v3. La respuesta incluye la clave privada del certificado emitido.

Requiere rol `admin` o `user`.

Body:

```json
{
  "common_name": "portal.edu.local",
  "certificate_type": "server",
  "owner": "admin",
  "organization": "EduPKIManager",
  "organizational_unit": "Education PKI",
  "country": "PE",
  "sans": ["portal.edu.local", "127.0.0.1"],
  "validity_days": 365,
  "key_algorithm": "rsa-2048"
}
```

Campos requeridos:

- `common_name`

Campos opcionales:

- `certificate_type`: default `user`
- `owner`: default actor autenticado; solo `admin` puede emitir para otro propietario
- `organization`: default `EduPKIManager`
- `organizational_unit`: default `Education PKI`
- `country`: default `PE`
- `sans`: default `[]`
- `validity_days`: default `365`
- `key_algorithm`: default `rsa-2048`

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/certificates/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"common_name":"portal.edu.local","certificate_type":"server","owner":"admin","sans":["portal.edu.local","127.0.0.1"],"validity_days":365}'
```

Restricciones por rol:

- `admin` puede emitir certificados `user`, `server` y `device`.
- `user` solo puede emitir certificados `user`; si solicita `server` o `device`, recibe `403`.
- Los certificados emitidos por `user` quedan con `owner` igual al actor autenticado.

Respuesta `201`:

```json
{
  "id": 1,
  "serial_number": "123456789",
  "common_name": "portal.edu.local",
  "certificate_type": "server",
  "owner": "admin",
  "status": "issued",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----...",
  "fingerprint_sha256": "abc123...",
  "not_before": "2026-06-24T23:00:00Z",
  "not_after": "2027-06-24T23:00:00Z",
  "revoked_at": null,
  "revocation_reason": ""
}
```

### `GET /certificates/{id}/`

Consulta el detalle de un certificado por identificador interno. No incluye la clave privada.

Requiere rol `admin` o `user`.

- `admin` puede consultar cualquier certificado.
- `user` solo puede consultar certificados propios.

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/certificates/1/ \
  -H "Authorization: Bearer <user_token>"
```

Respuesta `200`:

```json
{
  "id": 1,
  "serial_number": "123456789",
  "common_name": "portal.edu.local",
  "certificate_type": "server",
  "owner": "admin",
  "status": "issued",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "fingerprint_sha256": "abc123...",
  "not_before": "2026-06-24T23:00:00Z",
  "not_after": "2027-06-24T23:00:00Z",
  "revoked_at": null,
  "revocation_reason": ""
}
```

### `POST /certificates/validate/`

Valida la confianza completa de un certificado contra la PKI de EduPKIManager: cadena Root/Intermediate, firma de certificados, vigencia, BasicConstraints, KeyUsage, ExtendedKeyUsage, CertificatePolicies, CRL, OCSP y estado local.

Requiere rol `admin` o `user`.

Body por numero de serie:

```json
{
  "serial_number": "123456789",
  "purpose": "document_signing"
}
```

Body por PEM:

```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "purpose": "server_auth"
}
```

Valores de `purpose`:

- `document_signing`
- `server_auth`
- `client_auth`
- `device_auth`
- `any`

Respuesta `200`:

```json
{
  "valid": true,
  "purpose": "document_signing",
  "certificate": {
    "serial_number": "123456789",
    "subject": "CN=student.edu.local,OU=Education PKI,O=EduPKIManager,C=PE",
    "issuer": "CN=EduPKIManager Intermediate CA,OU=Intermediate Certification Authority,O=EduPKIManager,C=PE"
  },
  "chain": { "valid": true, "trust_anchor": "CN=EduPKIManager Root CA,OU=Root Certification Authority,O=EduPKIManager,C=PE" },
  "validity": { "valid": true },
  "key_usage": { "valid": true },
  "extended_key_usage": { "valid": true, "names": ["clientAuth", "emailProtection"] },
  "certificate_policies": { "valid": true, "oids": ["1.3.6.1.4.1.55555.1.1"] },
  "revocation": {
    "valid": true,
    "status": "good",
    "revoked_by_database": false,
    "revoked_by_crl": false,
    "ocsp": { "checked": true, "status": "GOOD", "signature_valid": true }
  },
  "errors": []
}
```

## Acciones de Certificado

Endpoint base:

```text
POST /certificates/{id}/{action}/
```

Acciones soportadas:

- `revoke`
- `suspend`
- `renew`

Si la accion no existe, responde `400`.

Todas las acciones requieren rol `admin`.

### `POST /certificates/{id}/revoke/`

Revoca un certificado y lo incluye en la CRL.

Body:

```json
{
  "reason": "key_compromise"
}
```

Si no se envia `reason`, usa `key_compromise`.

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/certificates/1/revoke/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"reason":"key_compromise"}'
```

Respuesta `200`:

```json
{
  "id": 1,
  "serial_number": "123456789",
  "common_name": "portal.edu.local",
  "certificate_type": "server",
  "owner": "admin",
  "status": "revoked",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "fingerprint_sha256": "abc123...",
  "not_before": "2026-06-24T23:00:00Z",
  "not_after": "2027-06-24T23:00:00Z",
  "revoked_at": "2026-06-24T23:30:00Z",
  "revocation_reason": "key_compromise"
}
```

### `POST /certificates/{id}/suspend/`

Suspende un certificado. El estado queda como `suspended` y la razon de revocacion como `certificate_hold`.

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/certificates/1/suspend/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{}'
```

Respuesta `200`:

```json
{
  "id": 1,
  "serial_number": "123456789",
  "common_name": "portal.edu.local",
  "certificate_type": "server",
  "owner": "admin",
  "status": "suspended",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "fingerprint_sha256": "abc123...",
  "not_before": "2026-06-24T23:00:00Z",
  "not_after": "2027-06-24T23:00:00Z",
  "revoked_at": "2026-06-24T23:30:00Z",
  "revocation_reason": "certificate_hold"
}
```

### `POST /certificates/{id}/renew/`

Marca el certificado original como `renewed` y emite un nuevo certificado con el mismo `common_name` y `certificate_type`.

Body opcional:

```json
{
  "validity_days": 365
}
```

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/certificates/1/renew/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"validity_days":365}'
```

Respuesta `200`:

```json
{
  "id": 2,
  "serial_number": "987654321",
  "common_name": "portal.edu.local",
  "certificate_type": "server",
  "owner": "admin",
  "status": "issued",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----...",
  "fingerprint_sha256": "def456...",
  "not_before": "2026-06-24T23:40:00Z",
  "not_after": "2027-06-24T23:40:00Z",
  "revoked_at": null,
  "revocation_reason": ""
}
```

## CRL

### `GET /crl.pem`

Descarga la version `latest` de la Lista de Revocacion de Certificados en formato PEM. Si el estado de revocacion cambio, publica una nueva version antes de responder.

Incluye certificados con estado:

- `revoked`
- `suspended`

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/crl.pem
```

Respuesta `200`:

Content-Type:

```text
application/x-pem-file
```

Body:

```text
-----BEGIN X509 CRL-----
...
-----END X509 CRL-----
```

### `GET /crl.der`

Descarga la version `latest` de la Lista de Revocacion de Certificados en formato DER.

Ejemplo:

```bash
curl -o crl.der http://127.0.0.1:8000/api/crl.der
```

Respuesta `200`:

Content-Type:

```text
application/pkix-crl
```

### `GET /crl/manifest/`

Devuelve el manifiesto de publicaciones CRL versionadas.

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/crl/manifest/
```

Respuesta `200`:

```json
{
  "current_number": 2,
  "latest_pem": "latest.crl.pem",
  "latest_der": "latest.crl.der",
  "versions": [
    {
      "number": 2,
      "created_at": "2026-07-12T10:00:00Z",
      "last_update": "2026-07-12T10:00:00Z",
      "next_update": "2026-07-12T22:00:00Z",
      "revoked_count": 1,
      "pem_path": "crl-2.pem",
      "der_path": "crl-2.der",
      "pem_sha256": "abc123...",
      "der_sha256": "def456...",
      "crl_number": 2
    }
  ]
}
```

### `GET /crl/{number}.pem`

Descarga una version historica especifica de la CRL en PEM.

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/crl/2.pem
```

### `GET /crl/{number}.der`

Descarga una version historica especifica de la CRL en DER.

Ejemplo:

```bash
curl -o crl-2.der http://127.0.0.1:8000/api/crl/2.der
```

## OCSP

### `POST /ocsp/`

Responder OCSP estandar RFC 6960. Recibe una solicitud OCSP DER y devuelve una respuesta OCSP DER firmada por la Intermediate CA.

Este endpoint tambien esta disponible fuera del prefijo API:

```text
POST https://edupkimanager.com/ocsp/
```

Content-Type de solicitud:

```text
application/ocsp-request
```

Content-Type de respuesta:

```text
application/ocsp-response
```

Ejemplo con OpenSSL:

```bash
openssl ocsp \
  -issuer intermediate-ca.pem \
  -cert cert.pem \
  -url https://edupkimanager.com/api/ocsp/ \
  -CAfile root-ca.pem \
  -resp_text
```

Estados soportados:

- `good`
- `revoked`
- `unknown`

Notas:

- Para seriales registrados, la respuesta refleja el estado persistido del certificado.
- Para seriales no registrados, la respuesta OCSP estandar devuelve estado `UNKNOWN`.
- Para requests malformados, responde con estado OCSP `MALFORMED_REQUEST`.

### `POST /ocsp/status/`

Consulta el estado OCSP de un certificado por numero de serie.

Body:

```json
{
  "serial_number": "123456789"
}
```

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/ocsp/status/ \
  -H "Content-Type: application/json" \
  -d '{"serial_number":"123456789"}'
```

Respuesta `200` para certificado existente:

```json
{
  "status": "good",
  "ocsp_der_base64": "MII...",
  "details": {
    "response_status": "SUCCESSFUL",
    "certificate_status": "GOOD",
    "serial_number": "123456789",
    "hash_algorithm": "sha256"
  }
}
```

Respuesta `200` para certificado no encontrado:

```json
{
  "status": "unknown"
}
```

Mapeo de estados:

- `issued` o `renewed`: `good`
- `revoked` o `suspended`: `revoked`
- no encontrado: `unknown`

## Firma PDF

### `POST /pdf/sign/`

Firma un documento PDF usando el certificado emitido por la CA propia. La firma es desprendida: se devuelve un sobre JSON con hash del documento, certificado, certificado de CA y firma en Base64.

Requiere rol `admin` o `user`.

El certificado debe estar en estado `issued`.

El rol `user` solo puede firmar con certificados propios. El rol `admin` puede operar con cualquier certificado emitido.

Body:

```json
{
  "serial_number": "123456789",
  "pdf_base64": "JVBERi0xLjQK..."
}
```

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/pdf/sign/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <user_token>" \
  -d '{"serial_number":"123456789","pdf_base64":"JVBERi0xLjQK"}'
```

Respuesta `200`:

```json
{
  "format": "EduPKIManager detached PDF signature v1",
  "actor": "usuario",
  "signed_at": "2026-06-24T23:50:00Z",
  "document_sha256": "abc123...",
  "certificate_serial_number": "123456789",
  "certificate_fingerprint_sha256": "def456...",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "ca_certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "signature_base64": "MEUCIQ...",
  "issuer_certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "signature_algorithm": "RSA-PKCS1v15-SHA256"
}
```

### `POST /pdf/sign-embedded/`

Firma un PDF de forma embebida usando PAdES-B-B. Devuelve el PDF firmado en Base64.

Requiere rol `admin` o `user`.

El certificado debe estar en estado `issued`.

El rol `user` solo puede firmar con certificados propios. El rol `admin` puede operar con cualquier certificado emitido.

Body:

```json
{
  "serial_number": "123456789",
  "pdf_base64": "JVBERi0xLjQK..."
}
```

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/pdf/sign-embedded/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <user_token>" \
  -d '{"serial_number":"123456789","pdf_base64":"JVBERi0xLjQK"}'
```

Respuesta `200`:

```json
{
  "format": "PAdES-B-B",
  "field_name": "EduPKIManagerSignature",
  "subfilter": "PADES",
  "signed_pdf_sha256": "abc123...",
  "signed_pdf_base64": "JVBERi0xLjQK..."
}
```

Si `pyHanko` no esta instalado, responde `501`.

### `POST /pdf/verify/`

Verifica una firma desprendida contra el contenido PDF enviado.

Requiere rol `admin` o `user`.

Body:

```json
{
  "pdf_base64": "JVBERi0xLjQK...",
  "signature_envelope": {
    "format": "EduPKIManager detached PDF signature v1",
    "actor": "usuario",
    "signed_at": "2026-06-24T23:50:00Z",
    "document_sha256": "abc123...",
    "certificate_serial_number": "123456789",
    "certificate_fingerprint_sha256": "def456...",
    "certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "signature_base64": "MEUCIQ...",
    "signature_algorithm": "RSA-PKCS1v15-SHA256"
  }
}
```

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/pdf/verify/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <user_token>" \
  -d '{"pdf_base64":"JVBERi0xLjQK","signature_envelope":{"format":"EduPKIManager detached PDF signature v1","document_sha256":"abc123","certificate_pem":"-----BEGIN CERTIFICATE-----...","signature_base64":"MEUCIQ...","signature_algorithm":"RSA-PKCS1v15-SHA256"}}'
```

Respuesta `200`:

```json
{
  "valid": true,
  "detached_signature_valid": true,
  "valid_trust": true,
  "valid_digest": true,
  "valid_signature": true,
  "valid_chain": true,
  "certificate_serial_number": "123456789",
  "chain_trust_anchor": "CN=EduPKIManager Root CA,OU=Root Certification Authority,O=EduPKIManager,C=PE",
  "trust_report": {
    "valid": true,
    "purpose": "document_signing",
    "revocation": {
      "status": "good",
      "revoked_by_database": false,
      "revoked_by_crl": false
    },
    "errors": []
  }
}
```

### `POST /pdf/verify-embedded/`

Verifica firmas PAdES embebidas dentro de un PDF firmado.

Requiere rol `admin` o `user`.

Body:

```json
{
  "signed_pdf_base64": "JVBERi0xLjQK..."
}
```

Ejemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/pdf/verify-embedded/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <user_token>" \
  -d '{"signed_pdf_base64":"JVBERi0xLjQK"}'
```

Respuesta `200`:

```json
{
  "valid": true,
  "signature_count": 1,
  "signed_pdf_sha256": "abc123...",
  "signatures": [
    {
      "field_name": "EduPKIManagerSignature",
      "valid": true,
      "trusted": true,
      "intact": true,
      "summary": "..."
    }
  ]
}
```

## TLS

### `GET /tls/demo/`

Ejecuta una demostracion de handshake TLS 1.3 entre cliente y servidor locales usando un certificado emitido por la CA propia.

Requiere rol `admin`.

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/tls/demo/ \
  -H "Authorization: Bearer <admin_token>"
```

Respuesta `200`:

```json
{
  "hostname": "edupkimanager.com",
  "client_tls_version": "TLSv1.3",
  "server_tls_version": "TLSv1.3",
  "server_reply": "ok"
}
```

El frontend Docker tambien expone HTTPS en:

```text
https://edupkimanager.com
```

Nginx queda restringido a `TLSv1.3` y usa un certificado de servidor emitido por la Intermediate CA mediante el servicio `tls_init`.

## Auditoria

### `GET /audit/`

Devuelve las ultimas 100 entradas del registro de auditoria y valida que el hash encadenado no haya sido alterado.

Requiere rol `admin`.

Ejemplo:

```bash
curl http://127.0.0.1:8000/api/audit/ \
  -H "Authorization: Bearer <admin_token>"
```

Respuesta `200`:

```json
{
  "valid_chain": true,
  "verification": {
    "entry_count": 42,
    "first_hash": "1111...",
    "last_hash": "abcd...",
    "broken_at_index": null,
    "errors": []
  },
  "entries": [
    {
      "schema_version": 2,
      "sequence_number": 42,
      "timestamp": "2026-06-24T23:50:00Z",
      "operation": "issue_certificate",
      "actor": "admin",
      "result": "success",
      "details": { "serial": "123456789" },
      "previous_hash": "0000...",
      "entry_hash": "abcd..."
    }
  ]
}
```

Cada entrada nueva incluye `previous_hash` y `entry_hash`; el `entry_hash` se calcula sobre el payload canonico de la entrada. Si una linea se modifica o se elimina, `verification.valid_chain` pasa a `false` y `broken_at_index` indica la primera linea inconsistente.

## Codigos y Errores Comunes

### `200 OK`

Operacion ejecutada correctamente.

### `201 Created`

Certificado emitido correctamente.

### `400 Bad Request`

Accion no soportada o payload invalido.

Ejemplo:

```json
{
  "detail": "Unsupported action."
}
```

### `401 Unauthorized`

Falta token o el token esta vencido/invalido.

### `403 Forbidden`

El usuario autenticado no tiene el rol requerido para la operacion.

Tambien ocurre si un usuario intenta consultar o usar un certificado cuyo `owner` pertenece a otro actor.

### `404 Not Found`

Puede ocurrir si se consulta una accion sobre un `id` de certificado inexistente.

### `500 Internal Server Error`

Puede ocurrir si faltan campos requeridos o si el payload no tiene el formato esperado. En la implementacion actual, algunas validaciones se delegan al runtime de Django/Python.

## Flujo End-to-End Recomendado

1. Verificar salud:

```bash
curl http://127.0.0.1:8000/api/health/
```

2. Emitir certificado:

```bash
curl -X POST http://127.0.0.1:8000/api/certificates/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"common_name":"portal.edu.local","certificate_type":"server","sans":["portal.edu.local"],"validity_days":365}'
```

3. Firmar PDF usando `serial_number`.

4. Verificar firma con el sobre devuelto.

5. Revocar certificado:

```bash
curl -X POST http://127.0.0.1:8000/api/certificates/1/revoke/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"reason":"key_compromise"}'
```

6. Descargar CRL:

```bash
curl http://127.0.0.1:8000/api/crl.pem
```

7. Consultar OCSP:

```bash
curl -X POST http://127.0.0.1:8000/api/ocsp/status/ \
  -H "Content-Type: application/json" \
  -d '{"serial_number":"123456789"}'
```
