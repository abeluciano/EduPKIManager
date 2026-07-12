# Progreso por Fases

## Fase 1 - Base PKI endurecida

Estado: completada.

Implementado:

- Root CA RSA-4096 autofirmada.
- Intermediate CA RSA-4096 firmada por la Root CA.
- Certificados finales emitidos por la Intermediate CA.
- Claves privadas de CA cifradas en reposo con `CA_KEY_PASSWORD`.
- Extensiones X.509 v3:
  - `BasicConstraints`
  - `KeyUsage`
  - `ExtendedKeyUsage`
  - `SubjectAlternativeName`
  - `SubjectKeyIdentifier`
  - `AuthorityKeyIdentifier`
  - `CRLDistributionPoints`
  - `AuthorityInformationAccess`
  - `CertificatePolicies`
- Validacion de tipo de certificado, pais, CN y periodo de validez.
- CRL y OCSP firmados por la Intermediate CA.
- TLS demo enviando leaf + Intermediate CA.
- Sobre de firma PDF con certificado leaf, Intermediate CA y Root CA.

Validado con:

```bash
PYTHONPATH=backend python -m unittest discover backend/tests
PYTHONPATH=backend python backend/scripts/e2e_demo.py
PYTHONPATH=backend python backend/scripts/tls13_demo.py
docker compose config
```

## Fase 2 - OCSP RFC 6960 real

Estado: completada.

Implementado:

- Endpoint binario `POST /ocsp/`.
- Endpoint binario `POST /api/ocsp/`.
- Parseo de `OCSPRequest` DER.
- Respuesta `OCSPResponse` DER compatible con OpenSSL.
- Content-Type `application/ocsp-request` y `application/ocsp-response`.
- Estados `GOOD`, `REVOKED` y `UNKNOWN`.
- Respuesta `MALFORMED_REQUEST` para payloads invalidos.
- Pruebas unitarias de respuestas DER.
- Smoke test API con request OCSP DER real.

Validacion OpenSSL:

```bash
openssl ocsp -issuer intermediate-ca.pem -cert cert.pem -url http://edupkimanager.com/api/ocsp/ -CAfile root-ca.pem -resp_text
```

## Fase 3 - CRL de produccion

Estado: completada.

Implementado:

- CRL versionada persistente.
- Archivos `crl-{number}.pem` y `crl-{number}.der`.
- Archivos `latest.crl.pem` y `latest.crl.der`.
- `manifest.json` con hashes, fechas, `CRLNumber`, conteo de revocados y rutas.
- Publicacion idempotente: no incrementa `CRLNumber` si no cambio el set revocado/suspendido.
- Scheduler `crl_scheduler` usando el publicador versionado.
- Endpoints:
  - `GET /api/crl.pem`
  - `GET /api/crl.der`
  - `GET /api/crl/manifest/`
  - `GET /api/crl/{number}.pem`
  - `GET /api/crl/{number}.der`
- Smoke test API para manifiesto y version especifica.
- Pruebas unitarias de incremento de version.

Validacion OpenSSL:

```bash
openssl crl -in crl-1.pem -noout -text
openssl verify -CAfile root-ca.pem -CRLfile latest.crl.pem -crl_check cert.pem
```

Nota: Delta CRL queda como mejora opcional futura; la fase base de CRL de produccion queda cubierta con versionado, `CRLNumber`, latest y manifiesto.

## Fase 4 - Firma PDF PAdES embebida

Estado: completada.

Implementado:

- Dependencia `pyHanko` en `backend/requirements.txt`.
- Firma PAdES-B-B embebida en `backend/pdf_sign/pades.py`.
- Verificacion de firmas embebidas con trust root de EduPKIManager.
- Endpoints:
  - `POST /api/pdf/sign-embedded/`
  - `POST /api/pdf/verify-embedded/`
- Frontend en `Operaciones`:
  - boton `Firmar PAdES`
  - descarga de PDF firmado
  - boton `Verificar PAdES`
- Smoke test API con firma/verificacion PAdES.
- Test unitario opcional que se activa si `pyHanko` esta instalado.

Validacion:

```bash
python backend/scripts/api_smoke_test.py http://127.0.0.1:8000/api
```

Nota: en entornos sin `pyHanko`, los endpoints PAdES devuelven `501` con mensaje claro. En Docker queda instalado por `requirements.txt`.

## Fase 5 - Verificacion completa de confianza

Estado: completada.

Implementado:

- Servicio central `backend/validation/trust.py`.
- Validacion de cadena:
  - certificado final firmado por Intermediate CA
  - Intermediate CA firmada por Root CA
  - Root CA autofirmada
- Validacion de vigencia temporal del certificado.
- Validacion de `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage` y `CertificatePolicies`.
- Validacion por proposito:
  - `document_signing`
  - `server_auth`
  - `client_auth`
  - `device_auth`
  - `any`
- Validacion de revocacion por:
  - estado local de base de datos
  - CRL actual firmada por la Intermediate CA
  - OCSP firmado por la Intermediate CA
- Endpoint:
  - `POST /api/certificates/validate/`
- Verificacion PDF desprendida enriquecida con `trust_report`.
- Frontend en `Operaciones`:
  - panel `Confianza X.509`
  - selector de proposito
  - desglose de cadena, vigencia, uso y revocacion
- Smoke test API para certificado valido y certificado suspendido.
- Pruebas unitarias de confianza para firma documental, servidor TLS y revocacion.

Validacion:

```bash
PYTHONPATH=backend python -m unittest discover backend/tests
PYTHONPATH=backend python backend/scripts/e2e_demo.py
python backend/scripts/api_smoke_test.py http://127.0.0.1:8000/api
```

## Fase 6 - TLS 1.3 con dominio local

Estado: completada.

Implementado:

- Dominio local objetivo: `edupkimanager.com`.
- Certificado TLS de servidor emitido por la Intermediate CA del sistema.
- SAN del certificado TLS:
  - `edupkimanager.com`
  - `www.edupkimanager.com`
  - `localhost`
  - `127.0.0.1`
- Servicio `tls_init` en Docker Compose:
  - monta `ca_data` para usar la CA
  - escribe solo el bundle TLS en `tls_certs`
  - evita montar claves de CA en el contenedor frontend
- Nginx expone:
  - HTTP `80`
  - HTTPS `443`
- Nginx HTTPS restringido a `TLSv1.3`.
- `EDUPKI_PUBLIC_BASE_URL` actualizado a `https://edupkimanager.com/api`.
- CORS y CSRF configurados para origen HTTPS.
- Endpoints directos de certificados publicos:
  - `GET /api/ca/root.pem`
  - `GET /api/ca/chain.pem`
- Script de bootstrap:
  - `backend/scripts/bootstrap_tls_certs.py`
- Script de verificacion HTTPS real:
  - `backend/scripts/verify_https_tls.py`
- Demo TLS ahora valida el hostname `edupkimanager.com`.

Validacion:

```bash
PYTHONPATH=backend python -m unittest discover backend/tests
PYTHONPATH=backend python backend/scripts/tls13_demo.py
docker compose config
npm run build
```

Verificacion manual del sitio levantado:

```bash
curl -o edupki-root-ca.pem http://127.0.0.1:8000/api/ca/root.pem
PYTHONPATH=backend python backend/scripts/verify_https_tls.py --ca-file edupki-root-ca.pem
```

## Fase 7 - Auditoria inmutable y trazabilidad completa

Estado: completada.

Implementado:

- Servicio de auditoria reforzado en `backend/audit/service.py`.
- Entradas nuevas con:
  - `schema_version`
  - `sequence_number`
  - `previous_hash`
  - `entry_hash`
- Reporte detallado de verificacion:
  - integridad global
  - cantidad de entradas
  - primer hash
  - ultimo hash
  - linea de ruptura
  - errores concretos
- Compatibilidad con logs ya existentes de fases anteriores.
- Deteccion de manipulacion de payload o ruptura de cadena.
- Endpoint `GET /api/audit/` enriquecido con objeto `verification`.
- Registro de operaciones criptograficas faltantes:
  - lectura/descarga de Root CA y cadena CA
  - publicacion y descarga de CRL
  - consulta OCSP JSON
  - respuesta OCSP RFC 6960 DER
  - bootstrap de certificado TLS
  - refresh programado de CRL
  - fallos de firma PAdES por dependencia o certificado no emitido
- Frontend de auditoria con conteo, ultimo hash, linea de ruptura y hash por entrada.
- Pruebas unitarias de manipulacion del log.

Validacion:

```bash
PYTHONPATH=backend python -m unittest discover backend/tests
PYTHONPATH=backend python backend/scripts/e2e_demo.py
npm run build
docker compose config
```

## Fase 8 - Roles, ownership y panel usuario/admin

Estado: completada.

Implementado:

- Campo persistente `owner` en `CertificateRecord`.
- Migracion `backend/api/migrations/0002_certificaterecord_owner.py`.
- Certificados antiguos quedan como `owner=admin`.
- Emision con ownership:
  - `admin` puede emitir `user`, `server` y `device`.
  - `admin` puede asignar `owner`.
  - `user` solo puede emitir certificados `user`.
  - certificados emitidos por `user` quedan con `owner` igual al actor autenticado.
- Listado de certificados por rol:
  - `admin` ve todos.
  - `user` ve solo certificados propios.
- Control de acceso por owner en:
  - `GET /api/certificates/{id}/`
  - `POST /api/certificates/validate/` por serial registrado
  - `POST /api/pdf/sign/`
  - `POST /api/pdf/sign-embedded/`
- Auditoria de intentos denegados:
  - `certificate_access_denied`
  - emision de tipo no permitido por `user`
- Renovacion preserva el `owner` del certificado original.
- Frontend:
  - admin emite con propietario visible.
  - tabla admin muestra `owner`.
  - usuario final solo solicita certificados personales.
  - usuario final lista y descarga certificados propios.
  - metricas de usuario reflejan sus certificados.
- Pruebas API de permisos preparadas para entorno con Django; en runtime local sin Django se omiten automaticamente.

Validacion:

```bash
PYTHONPATH=backend python -m unittest discover backend/tests
npm run build
docker compose up -d --build
```

## Fase 9 - Operabilidad, readiness y aceptacion de despliegue

Estado: completada.

Implementado:

- Endpoint publico `GET /api/readiness/`.
- Chequeos de readiness:
  - conexion a base de datos
  - disponibilidad de Root CA e Intermediate CA
  - publicacion CRL y manifiesto
  - integridad de auditoria
- Respuesta `503` cuando algun componente critico no esta listo.
- Healthcheck Docker para `backend` usando `http://127.0.0.1:8000/api/readiness/`.
- Healthcheck Docker para `frontend` usando `http://127.0.0.1/healthz`.
- Nginx expone `/healthz` en HTTP y HTTPS.
- `depends_on` endurecido:
  - `crl_scheduler`, `tls_init` y `frontend` esperan `backend` saludable.
  - `frontend` espera que `tls_init` termine correctamente.
- Script de aceptacion:
  - `backend/scripts/deployment_acceptance.py`
- La aceptacion valida el frontend por defecto en `http://localhost:3000/healthz` para no depender del puerto 80 del host.
- El smoke test API ahora valida readiness.
- Documentacion de readiness y aceptacion.

Validacion:

```bash
PYTHONPATH=backend python -m unittest discover backend/tests
PYTHONPATH=backend python -m compileall backend
npm run build
docker compose config
docker compose up -d --build
PYTHONPATH=backend python backend/scripts/deployment_acceptance.py
```

## Fase 10 - Evidencia reproducible de entrega

Estado: completada.

Implementado:

- Script de generacion de evidencias:
  - `backend/scripts/generate_evidence_bundle.py`
- Correccion de demo TLS:
  - `backend/scripts/tls13_demo.py` restaura el directorio global de CA despues de usar una CA temporal.
  - `backend/tests/test_tls13.py` valida que el demo no contamine el estado PKI del backend.
- Endurecimiento de bootstrap TLS:
  - `backend/tls/service.py` rechaza bundles TLS obsoletos si no coincide la Root CA activa o el Authority Key Identifier de la Intermediate CA.
- Carpeta de salida por ejecucion:
  - `artifacts/evidence/<run-id>/`
- Reporte Markdown:
  - `EVIDENCE_REPORT.md`
- Artefactos generados desde una API viva:
  - Root CA y cadena CA
  - certificado X.509 emitido
  - PDF original de demo
  - sobre de firma desprendida
  - PDF firmado PAdES cuando la dependencia esta disponible
  - respuestas OCSP `good` y `revoked` en DER
  - manifiesto CRL, CRL PEM y CRL DER
  - verificacion TLS 1.3
  - resumen de auditoria inmutable
- Flujo probado:
  - health/readiness
  - login admin/user
  - emision
  - validacion X.509
  - firma y verificacion PDF
  - OCSP JSON y RFC 6960
  - renovacion
  - suspension
  - revocacion
  - CRL
  - TLS 1.3
  - auditoria
- Evidencia generada:
  - `artifacts/evidence/20260712T221245Z/EVIDENCE_REPORT.md`

Validacion:

```bash
PYTHONPATH=backend python -m unittest discover backend/tests
PYTHONPATH=backend python -m compileall backend
docker compose up -d --build
python backend/scripts/deployment_acceptance.py
python backend/scripts/api_smoke_test.py http://127.0.0.1:8000/api
PYTHONPATH=backend/scripts python backend/scripts/generate_evidence_bundle.py
```

## Fase 11 - Hardening de configuracion y runbook operativo

Estado: completada.

Implementado:

- Configuracion Docker externalizada con variables de entorno y defaults demo:
  - PostgreSQL
  - CA key password
  - Django secret/debug/allowed hosts
  - credenciales demo admin/user
  - CORS/CSRF
  - puertos publicados
  - hostname/SAN TLS
  - intervalo del scheduler CRL
- Archivo `.env.example` con variables esperadas.
- `.gitignore` para evitar subir `.env`, datos CA, artefactos y builds locales.
- Parseo robusto de listas en `backend/edupki/settings.py`.
- Scripts de aceptacion/evidencia/smoke usan passwords desde `EDUPKI_ADMIN_PASSWORD` y `EDUPKI_USER_PASSWORD`.
- Script de validacion de configuracion:
  - `backend/scripts/check_deployment_config.py`
- Runbook operativo:
  - `DEPLOYMENT_RUNBOOK.md`

Validacion:

```bash
python backend/scripts/check_deployment_config.py --env-file .env.example --profile demo
docker compose config
PYTHONPATH=backend python -m unittest discover backend/tests
PYTHONPATH=backend python -m compileall backend
```

## Fase 12 - Separacion visual por rol y preparacion TLS local

Estado: completada.

Implementado:

- Frontend separado visualmente por rol:
  - `admin`: `Administracion` y `Operaciones PKI`.
  - `user`: `Mi portal` y `Firmas y validacion`.
- Se elimina la pestaña generica `Usuario` para el administrador.
- Las metricas cambian de etiqueta segun rol.
- Helper Windows para preparar dominio TLS local:
  - `scripts/setup_windows_tls.ps1`
- Runbook y README explican:
  - entrada `hosts` para `edupkimanager.com`
  - descarga de Root CA
  - importacion opcional de Root CA con `-TrustRootCa`

Validacion esperada:

```bash
npm run build
docker compose up -d --build
python backend/scripts/deployment_acceptance.py
```
