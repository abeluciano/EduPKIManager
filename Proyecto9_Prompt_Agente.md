# Prompt para Agente — EduPKIManager

Eres un ingeniero de software senior especializado en criptografía y seguridad de infraestructura. Tu tarea es desarrollar "EduPKIManager", una plataforma completa de Infraestructura de Clave Pública (PKI) orientada a entornos empresariales educativos.

---

## Stack Tecnológico

- **Backend:** Python con Django REST Framework
- **Criptografía:** librería `cryptography` de Python (PyCA) y OpenSSL bindings
- **Algoritmos:** RSA-2048/4096, ECDSA (P-256), SHA-256/512
- **Frontend:** React.js + TypeScript
- **Base de datos:** PostgreSQL
- **Despliegue:** Docker Compose

---

## Módulos a Implementar

### 1. Root CA — Autoridad Certificadora Raíz
- Generar par de claves RSA-4096 para la CA raíz
- Crear certificado autofirmado X.509 v3 para la Root CA
- Almacenar la clave privada de forma segura (cifrada en reposo)

### 2. Emisión de Certificados X.509 v3
- Endpoint API REST para emitir certificados para usuarios, servidores y dispositivos
- Incluir todos los campos estándar: CN, O, OU, C, SAN, validez, uso de clave (KeyUsage, ExtendedKeyUsage)

### 3. Gestión del Ciclo de Vida de Certificados
- Endpoints para: emitir, renovar, suspender y revocar certificados
- Persistencia del estado de cada certificado en PostgreSQL

### 4. CRL — Lista de Revocación de Certificados
- Generación automática y periódica de la CRL firmada por la CA
- Endpoint público para descarga de la CRL en formato DER y PEM

### 5. OCSP — Online Certificate Status Protocol
- Servidor OCSP que responda consultas de estado de certificados en tiempo real
- Respuestas firmadas por la CA con estados: good, revoked, unknown

### 6. Módulo de Firma Digital de Documentos PDF
- Firmar documentos PDF usando certificados emitidos por la CA propia
- Verificar firmas con trazabilidad completa de la cadena de confianza

### 7. Handshake TLS 1.3
- Configurar servidor HTTPS usando certificados emitidos por la CA del sistema
- Demostrar handshake TLS 1.3 funcional entre cliente y servidor

### 8. Panel de Administración Web (React.js + TypeScript)
- **Vista administrador:** listar, emitir, revocar y renovar certificados
- **Vista usuario final:** solicitar certificado, descargarlo y ver su estado
- Autenticación con roles: administrador y usuario final

### 9. Registro de Auditoría Inmutable
- Log de todas las operaciones criptográficas: emisión, revocación, firma, verificación
- Cada entrada debe incluir: timestamp, operación, actor, resultado y hash encadenado de la entrada anterior (estructura tipo blockchain ligera)

---

## Estructura de Carpetas Esperada

```
EduPKIManager/
├── backend/
│   ├── ca/               # Root CA y emisión de certificados
│   ├── crl/              # Generación de CRL
│   ├── ocsp/             # Servidor OCSP
│   ├── pdf_sign/         # Firma y verificación de PDFs
│   ├── tls/              # Configuración TLS 1.3
│   ├── audit/            # Registro de auditoría inmutable
│   ├── api/              # Endpoints REST (Django REST Framework)
│   └── models/           # Modelos PostgreSQL
├── frontend/
│   ├── admin/            # Panel administrador
│   └── user/             # Portal usuario final
├── docker-compose.yml
└── README.md
```

---

## Entregables

1. Código fuente completo con comentarios explicativos
2. `docker-compose.yml` funcional que levante todo el sistema con un solo comando
3. `README.md` con instrucciones de instalación, configuración y uso
4. Colección Postman o script de pruebas para todos los endpoints de la API
5. Demo end-to-end documentada: emisión de certificado → firma de PDF → verificación → revocación → CRL actualizada

---

## Instrucciones de Ejecución

Desarrolla los módulos en el orden listado. Comienza por la estructura base del proyecto y el módulo de Root CA, luego avanza módulo por módulo hasta completar el panel web y el registro de auditoría. Tras cada módulo, confirma que compila y que los tests unitarios pasan antes de continuar con el siguiente.
