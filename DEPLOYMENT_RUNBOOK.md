# EduPKIManager Deployment Runbook

## 1. Preparar configuracion

Copia el archivo de ejemplo y cambia todos los secretos:

```bash
cp .env.example .env
```

Valores obligatorios para un despliegue serio:

| Variable | Uso |
| --- | --- |
| `POSTGRES_PASSWORD` | Password de PostgreSQL |
| `CA_KEY_PASSWORD` | Cifrado de claves privadas de la CA |
| `DJANGO_SECRET_KEY` | Firma interna de Django y tokens demo |
| `EDUPKI_ADMIN_PASSWORD` | Password del usuario administrador demo |
| `EDUPKI_USER_PASSWORD` | Password del usuario final demo |
| `DJANGO_DEBUG` | Debe ser `0` fuera de demo |
| `DJANGO_ALLOWED_HOSTS` | Hosts permitidos por Django |
| `CORS_ALLOWED_ORIGINS` | Origenes permitidos del frontend |
| `CSRF_TRUSTED_ORIGINS` | Origenes confiables para CSRF |

Importante: no cambies `CA_KEY_PASSWORD` despues de generar la CA en el volumen `ca_data`, porque las claves privadas existentes estan cifradas con el password anterior. Si necesitas rotarlo, haz una ceremonia de rotacion o reinicia la CA en un entorno limpio.

## 2. Validar configuracion

Modo demo:

```bash
python backend/scripts/check_deployment_config.py --env-file .env.example --profile demo
```

Modo produccion:

```bash
python backend/scripts/check_deployment_config.py --env-file .env --profile production
```

## 3. Configurar dominio local

Agrega en el archivo `hosts`:

```text
127.0.0.1 edupkimanager.com www.edupkimanager.com
```

En Windows:

```text
C:\Windows\System32\drivers\etc\hosts
```

Tambien puedes ejecutar PowerShell como administrador desde la raiz del proyecto:

```powershell
.\scripts\setup_windows_tls.ps1
```

Para que Edge/Chrome confien en el certificado HTTPS emitido por la CA propia, ejecuta:

```powershell
.\scripts\setup_windows_tls.ps1 -TrustRootCa
```

Esto agrega `edupkimanager.com` al archivo `hosts`, descarga la Root CA desde la API y, con `-TrustRootCa`, la importa al almacen `CurrentUser\Root`.

## 4. Levantar servicios

```bash
docker compose up -d --build
docker compose ps
```

Servicios esperados:

| Servicio | Estado esperado |
| --- | --- |
| `db` | healthy |
| `backend` | healthy |
| `frontend` | healthy |
| `crl_scheduler` | up |
| `tls_init` | completed successfully |

## 5. Validar aceptacion

```bash
python backend/scripts/deployment_acceptance.py
python backend/scripts/api_smoke_test.py
```

La aceptacion comprueba readiness, health del frontend, auditoria y HTTPS con TLS 1.3 usando la CA propia.

## 6. Generar evidencia final

```bash
python backend/scripts/generate_evidence_bundle.py
```

Salida:

```text
artifacts/evidence/<run-id>/EVIDENCE_REPORT.md
```

El bundle incluye certificado emitido, cadena CA, PDF firmado, respuestas OCSP, CRL, verificacion TLS 1.3 y resumen de auditoria.

## 7. URLs locales

| Recurso | URL |
| --- | --- |
| Frontend HTTP | `http://localhost:3000` |
| Frontend dominio local | `http://edupkimanager.com` |
| Frontend HTTPS | `https://edupkimanager.com` |
| API | `http://127.0.0.1:8000/api` |
| Readiness | `http://127.0.0.1:8000/api/readiness/` |
| Root CA | `http://127.0.0.1:8000/api/ca/root.pem` |

Para evitar advertencias del navegador en HTTPS, importa `root-ca.pem` como autoridad confiable en tu sistema o navegador.
