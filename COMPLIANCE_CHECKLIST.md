# Matriz de Cumplimiento - EduPKIManager

## Requisitos Funcionales

| Requisito | Estado | Implementacion |
| --- | --- | --- |
| Root CA RSA-4096 con certificado X.509 v3 autofirmado | Cumplido | `backend/ca/service.py`, `ensure_root_ca()` |
| Intermediate CA separada de Root CA | Cumplido | `ensure_intermediate_ca()`, certificados leaf emitidos por la intermedia |
| Clave privada de CA cifrada en reposo | Cumplido | `serialization.BestAvailableEncryption`, variable `CA_KEY_PASSWORD` |
| Emision X.509 v3 para usuarios, servidores y dispositivos | Cumplido | `POST /api/certificates/`, `CertificateRequest`, `KeyUsage`, `ExtendedKeyUsage`, SAN, CRL DP, AIA/OCSP, CertificatePolicies |
| Ciclo de vida: emision, renovacion, suspension y revocacion | Cumplido | `POST /api/certificates/`, `POST /api/certificates/{id}/renew/`, `suspend/`, `revoke/` |
| Persistencia PostgreSQL | Cumplido | `docker-compose.yml` servicio `db`, modelo `CertificateRecord` |
| CRL actualizada automaticamente y descargable en PEM/DER | Cumplido | `GET /api/crl.pem`, `GET /api/crl.der`, servicio `crl_scheduler` |
| CRL versionada con manifiesto y CRLNumber persistente | Cumplido | `GET /api/crl/manifest/`, `GET /api/crl/{number}.pem`, `GET /api/crl/{number}.der`, `backend/crl/publication.py` |
| OCSP con estados good, revoked, unknown | Cumplido | `POST /api/ocsp/` RFC 6960 DER, `POST /ocsp/`, y endpoint JSON `POST /api/ocsp/status/` |
| Firma digital de PDF con certificado de la CA | Cumplido | Firma desprendida `POST /api/pdf/sign/` y PAdES embebido `POST /api/pdf/sign-embedded/` |
| Verificacion de firma y trazabilidad de cadena | Cumplido | `POST /api/pdf/verify/`, `POST /api/pdf/verify-embedded/`, `POST /api/certificates/validate/`, valida firma, integridad, cadena Root/Intermediate, vigencia, usos permitidos, politicas, CRL, OCSP y estado local |
| Handshake TLS 1.3 con certificado emitido por CA propia | Cumplido | `https://edupkimanager.com`, Nginx `ssl_protocols TLSv1.3`, servicio `tls_init`, `GET /api/tls/demo/`, `backend/scripts/tls13_demo.py`, `backend/scripts/verify_https_tls.py` |
| Panel web administrador | Cumplido | Login admin, listado completo, emision con propietario, renovacion, suspension y revocacion en `frontend/src/admin/AdminPanel.tsx` |
| Panel web usuario final | Cumplido | Login usuario, solicitud de certificados personales, listado propio, descarga y estado de certificado en `frontend/src/user/UserPortal.tsx` |
| Operaciones PKI en frontend | Cumplido | Firma/verificacion PDF, OCSP, Root CA, CRL, TLS y auditoria en `frontend/src/tools/PkiTools.tsx` |
| Autenticacion con roles | Cumplido | `POST /api/auth/login/`, token firmado, permisos admin/user, ownership de certificados y bloqueo de acceso cruzado en `backend/api/views.py` |
| Auditoria inmutable | Cumplido | `backend/audit/service.py`, secuencia, hash encadenado, reporte de verificacion, deteccion de manipulacion, `GET /api/audit/`, eventos de CA, CRL, OCSP, certificados, PDF y TLS |
| Configuracion externalizada para despliegue | Cumplido | `.env.example`, `docker-compose.yml` con variables, `backend/scripts/check_deployment_config.py`, `DEPLOYMENT_RUNBOOK.md` |

## Entregables

| Entregable | Estado | Archivo |
| --- | --- | --- |
| Codigo fuente completo | Cumplido | `backend/`, `frontend/` |
| Docker Compose funcional | Cumplido | `docker-compose.yml` |
| README de instalacion, configuracion y uso | Cumplido | `README.md` |
| Runbook de despliegue y operacion | Cumplido | `DEPLOYMENT_RUNBOOK.md` |
| Coleccion Postman o script de pruebas | Cumplido | `postman_collection.json`, `backend/scripts/api_smoke_test.py`, `backend/scripts/deployment_acceptance.py`, `backend/scripts/generate_evidence_bundle.py` |
| Demo end-to-end documentada | Cumplido | `README.md`, `backend/scripts/e2e_demo.py` |
| Evidencia reproducible de entrega | Cumplido | `artifacts/evidence/<run-id>/EVIDENCE_REPORT.md` generado por `backend/scripts/generate_evidence_bundle.py` |

## Comandos de Verificacion

```bash
PYTHONPATH=backend python -m unittest discover backend/tests
PYTHONPATH=backend python backend/scripts/e2e_demo.py
PYTHONPATH=backend python backend/scripts/tls13_demo.py
python backend/scripts/api_smoke_test.py http://127.0.0.1:8000/api
PYTHONPATH=backend python backend/scripts/deployment_acceptance.py
PYTHONPATH=backend/scripts python backend/scripts/generate_evidence_bundle.py
python backend/scripts/check_deployment_config.py --env-file .env.example --profile demo
docker compose up --build
```
