# EduPKIManager

EduPKIManager es una plataforma PKI para entornos educativos. Incluye una CA raiz propia, emision de certificados X.509 v3, ciclo de vida de certificados, CRL, respuestas OCSP, firma desprendida de PDFs, TLS 1.3 con certificado emitido por la CA propia, panel web y auditoria inmutable con hash encadenado.

## Componentes

- `backend/ca`: Root CA RSA-4096, Intermediate CA RSA-4096 y emision de certificados RSA/ECDSA.
- `backend/crl`: generacion de CRL firmada en PEM y DER.
- `backend/ocsp`: respuestas OCSP firmadas por la CA.
- `backend/pdf_sign`: firma y verificacion desprendida para documentos PDF.
- `backend/pdf_sign/pades.py`: firma y verificacion PAdES embebida con `pyHanko`.
- `backend/validation`: validacion de confianza X.509, usos permitidos, CRL, OCSP y estado local.
- `backend/tls`: emision idempotente de bundle de servidor y contexto TLS 1.3.
- `backend/audit`: registro JSONL append-only con hash encadenado, secuencia y reporte de verificacion.
- `backend/api`: API Django REST Framework.
- `frontend`: consola React + TypeScript para administrador y usuario final.

## Ejecucion con Docker

```bash
docker compose up --build
```

Servicios:

- API: `http://127.0.0.1:8000/api`
- Panel web HTTPS: `https://edupkimanager.com`
- Panel web HTTP de respaldo: `http://edupkimanager.com` o `http://localhost:3000`
- PostgreSQL: servicio interno `db`
- Scheduler CRL: servicio interno `crl_scheduler`, publica CRL versionadas y refresca `data/crl/latest.crl.pem` y `data/crl/latest.crl.der`
- Bootstrap TLS: servicio interno `tls_init`, genera `server_cert.pem`, `server_key.pem` y `root_ca_cert.pem` en el volumen `tls_certs`

La configuracion se puede externalizar con `.env`. Copia `.env.example` a `.env`, cambia secretos y valida el archivo antes de un despliegue serio:

```bash
python backend/scripts/check_deployment_config.py --env-file .env --profile production
```

En produccion cambia `CA_KEY_PASSWORD`, `DJANGO_SECRET_KEY`, `POSTGRES_PASSWORD` y las credenciales demo.

## Dominio Local

El proyecto esta preparado para usar `edupkimanager.com` como dominio local de desarrollo, aunque no este comprado. Agrega esta linea al archivo `hosts` de tu sistema:

```text
127.0.0.1 edupkimanager.com www.edupkimanager.com
```

En Windows, abre Bloc de notas como administrador y edita:

```text
C:\Windows\System32\drivers\etc\hosts
```

Despues levanta Docker:

```bash
docker compose up --build
```

Abre el sitio HTTPS:

```text
https://edupkimanager.com
```

Si `edupkimanager.com` no abre, falta la entrada del archivo `hosts`. En Windows puedes preparar el dominio local con PowerShell como administrador:

```powershell
.\scripts\setup_windows_tls.ps1
```

El certificado HTTPS esta emitido por la Root CA propia del sistema. Para que el navegador no muestre advertencia, importa como autoridad de confianza el certificado descargado desde:

```text
http://127.0.0.1:8000/api/ca/root.pem
```

O usa el helper:

```powershell
.\scripts\setup_windows_tls.ps1 -TrustRootCa
```

### Quitar la configuracion TLS local de Windows

Detener o eliminar los contenedores no revierte los cambios de Windows. Para quitar la entrada de `hosts`, retirar la Root CA de confianza de `CurrentUser\Root` y borrar el certificado descargado por el helper, abre PowerShell como administrador en la raiz del proyecto y ejecuta:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\setup_windows_tls.ps1 -Remove
```

El cambio de politica con `-Scope Process` solo afecta esa ventana de PowerShell. Al cerrarla se descarta automaticamente y no modifica permanentemente la politica del sistema.

Despues de ejecutar `-Remove`, `https://edupkimanager.com` dejara de apuntar a esta computadora. Mientras los contenedores sigan activos, la aplicacion todavia estara disponible mediante `http://localhost:3000`.

Tambien puedes abrir el respaldo HTTP mientras haces esa instalacion:

```text
http://edupkimanager.com
```

## Acceso

Usuarios demo:

- Administrador: `admin` / `admin123`
- Universidad la Salle: `lasalle` / `lasalle123`
- Abel Aragon: `abel.aragon` / `abel123`
- Carlos Mijail: `carlos.mijail` / `carlos123`
- Josshua Flores: `josshua.flores` / `josshua123`
- Marco Alatrista: `marco.alatrista` / `marco123`

El login emite un token firmado que el frontend envia como `Authorization: Bearer <token>`. Las acciones de administracion requieren rol `admin`; los certificados guardan `owner`; los cinco usuarios finales solo listan, descargan, firman y verifican PDFs con certificados emitidos para su propietario por el administrador.

## Panel Web

- Rol `admin`: ve `Administracion` y `Operaciones PKI`.
- Rol `user`: ve `Mi portal` y `Firmas PDF`.
- `Administracion`: emision para uno de los cinco propietarios definidos, listado paginado, consulta de numero de serie y huella, descarga, renovacion, suspension y revocacion de certificados.
- `Mi portal`: listado paginado, numero de serie, estado y descarga de certificados emitidos por el administrador para el propietario autenticado.
- `Operaciones PKI`: para administradores incluye firma/verificacion PDF, consulta OCSP, validacion X.509, descarga de Root CA/CRL, demo TLS 1.3 y auditoria verificable.
- `Firmas PDF`: para usuarios finales incluye solo firma y verificacion PDF.

Las operaciones de firma permiten dos formatos de PDF:

- Firma desprendida JSON, mantenida por compatibilidad.
- Firma embebida PAdES-B-B, que devuelve un PDF firmado descargable.
- Validacion de confianza X.509 por proposito: firma documental, TLS servidor, cliente, dispositivo o general.

Los archivos PDF tienen un limite de 10 MB. La interfaz valida el archivo antes de enviarlo y muestra mensajes breves para archivos invalidos, demasiado grandes o con una estructura de referencias hibridas no compatible con PAdES.

## CRL Versionada

La CRL se publica con versiones persistentes:

```text
data/crl/crl-1.pem
data/crl/crl-1.der
data/crl/latest.crl.pem
data/crl/latest.crl.der
data/crl/manifest.json
```

El numero `CRLNumber` aumenta solo cuando cambia el conjunto de certificados revocados o suspendidos. El manifiesto esta disponible en:

```text
GET /api/crl/manifest/
```

## Cadena PKI

La plataforma usa una cadena de confianza de tres niveles:

```text
EduPKIManager Root CA
  -> EduPKIManager Intermediate CA
      -> Certificados de usuario, servidor y dispositivo
```

La Root CA actua como ancla de confianza. La Intermediate CA firma certificados finales, CRL y respuestas OCSP. Los certificados emitidos incluyen extensiones X.509 para CRL, AIA/OCSP, politicas, KeyUsage, ExtendedKeyUsage, SAN y Authority/Subject Key Identifier.

## OCSP Estandar

El responder OCSP RFC 6960 esta disponible en:

```text
https://edupkimanager.com/api/ocsp/
https://edupkimanager.com/ocsp/
```

Ejemplo:

```bash
openssl ocsp -issuer intermediate-ca.pem -cert cert.pem -url https://edupkimanager.com/api/ocsp/ -CAfile root-ca.pem -resp_text
```

## Flujo principal

1. Login: `POST /api/auth/login/`
2. Emitir certificado: `POST /api/certificates/`
3. Firmar PDF: `POST /api/pdf/sign/`
4. Firmar PDF embebido PAdES: `POST /api/pdf/sign-embedded/`
5. Verificar firma: `POST /api/pdf/verify/`
6. Verificar PDF PAdES: `POST /api/pdf/verify-embedded/`
7. Validar confianza X.509: `POST /api/certificates/validate/`
8. Revocar certificado: `POST /api/certificates/{id}/revoke/`
9. Descargar CRL: `GET /api/crl.pem` o `GET /api/crl.der`
10. Consultar OCSP: `POST /api/ocsp/status/`
11. Probar TLS 1.3: `GET /api/tls/demo/`
12. Ver auditoria: `GET /api/audit/`

## Pruebas

Pruebas unitarias de la capa criptografica:

```bash
python -m unittest discover backend/tests
```

Demo local sin levantar Django:

```bash
PYTHONPATH=backend python backend/scripts/e2e_demo.py
```

Demo TLS 1.3:

```bash
PYTHONPATH=backend python backend/scripts/tls13_demo.py
```

Prueba contra la API ya levantada:

```bash
python backend/scripts/api_smoke_test.py http://127.0.0.1:8000/api
```

Prueba de aceptacion del despliegue Docker:

```bash
PYTHONPATH=backend python backend/scripts/deployment_acceptance.py
```

Por defecto valida el frontend en `http://localhost:3000/healthz`, para evitar conflictos con servicios locales que ocupen el puerto 80.

Generar evidencias de entrega en Markdown y artefactos criptograficos:

```bash
PYTHONPATH=backend/scripts python backend/scripts/generate_evidence_bundle.py
```

El reporte se crea en `artifacts/evidence/<run-id>/EVIDENCE_REPORT.md` junto con certificados, CRL, respuestas OCSP, PDF firmado y resumen de auditoria.

Validar configuracion de despliegue:

```bash
python backend/scripts/check_deployment_config.py --env-file .env.example --profile demo
```

Tambien puedes importar `postman_collection.json` en Postman.

## TLS 1.3

El modulo `backend/tls/service.py` genera un certificado de servidor emitido por la CA propia y crea un contexto `ssl` con version minima TLS 1.3. Ejemplo:

```python
from tls.service import issue_tls_server_bundle, tls13_context

bundle = issue_tls_server_bundle("edupkimanager.com")
context = tls13_context(bundle["certificate"], bundle["private_key"])
```

En Docker, Nginx sirve el frontend en `443` con:

```text
ssl_protocols TLSv1.3;
ssl_certificate /etc/nginx/edupki/server_cert.pem;
ssl_certificate_key /etc/nginx/edupki/server_key.pem;
```

Verificacion opcional contra el endpoint HTTPS levantado:

```bash
curl -o edupki-root-ca.pem http://127.0.0.1:8000/api/ca/root.pem
PYTHONPATH=backend python backend/scripts/verify_https_tls.py --ca-file edupki-root-ca.pem
```

## Nota de firma PDF

El modulo de PDF genera una firma desprendida con SHA-256 y la clave privada del certificado emitido. La verificacion desprendida valida integridad, firma, cadena Root/Intermediate, uso documental, estado local, CRL y OCSP. Para PAdES embebido se usa `pyHanko` con la Root CA de EduPKIManager como ancla de confianza.

## Documentacion

- Endpoints: `API_ENDPOINTS.md`
- Cumplimiento de requisitos: `COMPLIANCE_CHECKLIST.md`
- Runbook de despliegue: `DEPLOYMENT_RUNBOOK.md`
- Coleccion Postman: `postman_collection.json`
