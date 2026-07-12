# Proyecto 9: "Plataforma de Gestión de Infraestructura de Clave Pública (PKI)"

**Nivel:** 3

**Categorías:** PKI, Certificados X.509, Firmas Digitales, Criptografía Asimétrica

---

## Objetivo

Desarrollar una plataforma completa de Infraestructura de Clave Pública que implemente una Autoridad Certificadora (CA) propia, gestión del ciclo de vida de certificados digitales, firmas digitales de documentos y soporte para protocolo TLS, orientada a entornos empresariales educativos.

---

## Título del Software

EduPKIManager

---

## Tecnologías sugeridas

- Lenguaje: Python / Java (Spring Boot)
- Criptografía: cryptography (Python) u OpenSSL bindings
- Algoritmos: RSA-2048/4096, ECDSA (P-256), SHA-256/512
- Backend: Django REST Framework
- Frontend: React.js + TypeScript
- Base de datos: PostgreSQL
- Despliegue: Docker Compose

---

## Requisitos Funcionales

1. Implementación de Autoridad Certificadora raíz (Root CA) con generación de par de claves RSA-4096.
2. Emisión de certificados X.509 v3 para usuarios, servidores y dispositivos con campos estándar completos.
3. Gestión del ciclo de vida de certificados: emisión, renovación, suspensión y revocación.
4. Publicación y consulta de Lista de Revocación de Certificados (CRL) actualizada automáticamente.
5. Soporte de protocolo OCSP (Online Certificate Status Protocol) para verificación en línea de estado.
6. Módulo de firma digital de documentos PDF con certificado emitido por la CA propia.
7. Verificación de firmas digitales con trazabilidad completa de la cadena de confianza.
8. Implementación de handshake TLS 1.3 usando certificados emitidos por la CA del sistema.
9. Panel de administración web para gestión completa de certificados con roles: administrador y usuario final.
10. Registro de auditoría inmutable de todas las operaciones criptográficas realizadas en la plataforma.
