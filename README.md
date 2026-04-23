# VaultChain
**Sistema de Mensajería Segura con Registro Inmutable**  
Proyecto 2 — Cifrado de Información · Entrega 1: Autenticación y Gestión de Llaves

---

## Descripción

VaultChain es una API REST construida con **FastAPI** que implementa un sistema de registro e inicio de sesión seguro. En esta primera entrega se establece la base criptográfica del sistema: hashing de contraseñas, generación y protección de pares de llaves asimétricas, y autenticación mediante JWT.

---

## Stack

| Capa | Tecnología |
|---|---|
| Framework | FastAPI 0.115 |
| ORM | SQLAlchemy 2.0 |
| Base de datos | PostgreSQL (Supabase) |
| Criptografía | PyCryptodome 3.20 |
| Tokens | python-jose (JWT HS256) |

---

## Tabla de base de datos

### `users`

| Columna | Tipo | Descripción |
|---|---|---|
| `id` | UUID (PK) | Identificador único generado automáticamente |
| `email` | VARCHAR(255) | Correo electrónico, único y requerido |
| `display_name` | VARCHAR(100) | Nombre visible del usuario |
| `password_hash` | VARCHAR(255) | Hash bcrypt de la contraseña |
| `public_key` | TEXT | Llave pública RSA-2048 en formato PEM |
| `encrypted_private_key` | TEXT | Llave privada cifrada con AES-256-GCM (ver abajo) |
| `totp_secret` | VARCHAR(32) | Secreto TOTP para 2FA (reservado para entregas futuras) |
| `created_at` | TIMESTAMPTZ | Fecha de creación (automática) |

---

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| `POST` | `/auth/register` | Registra un nuevo usuario |
| `POST` | `/auth/login` | Inicio de sesión, retorna tokens JWT |
| `GET` | `/users/{user_id}/key` | Retorna la llave pública PEM del usuario |
| `DELETE` | `/users/{user_id}` | Elimina un usuario (uso en pruebas de integración) |

### `POST /auth/register`
**Body:**
```json
{
  "display_name": "Nombre Apellido",
  "email": "usuario@ejemplo.com",
  "password": "ContraseñaSegura#2026"
}
```
**Respuesta 201:**
```json
{
  "user_id": "uuid",
  "email": "usuario@ejemplo.com",
  "display_name": "Nombre Apellido",
  "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### `POST /auth/login`
**Body:**
```json
{
  "email": "usuario@ejemplo.com",
  "password": "ContraseñaSegura#2026"
}
```
**Respuesta 200:**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "user_id": "uuid",
  "display_name": "Nombre Apellido"
}
```

---

## Seguridad criptográfica

### Hashing de contraseñas — bcrypt

Las contraseñas se hashean con **bcrypt** antes de almacenarse. bcrypt incorpora un salt aleatorio por diseño y es intencionalmente lento para resistir ataques de fuerza bruta. Nunca se almacena la contraseña en texto plano.

```python
password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
```

### Generación de par de llaves — RSA-2048 y ECC P-256

Al registrarse, el servidor genera automáticamente un par de llaves asimétricas para el usuario. El sistema soporta dos algoritmos:

| Algoritmo | Tamaño | Uso |
|---|---|---|
| RSA-2048 | 2048 bits | Par de llaves por defecto en el registro |
| ECC P-256 | 256 bits (equivalente ~3072 RSA) | Disponible como alternativa |

La llave pública se almacena en texto plano en la base de datos (es pública por definición). La llave privada **nunca se almacena en texto plano**.

### Flujo de registro

Al recibir un `POST /auth/register`, la contraseña del usuario es utilizada de dos formas independientes en paralelo:

```
Contraseña del usuario
       │
       ├──► bcrypt.hashpw() ──────────────────────► password_hash         (guardado en DB)
       │
       └──► PBKDF2(password, salt) ──► AES-256-GCM(private_pem)
                                                      │
                             generate_rsa_keypair() ──┤
                                    │                 │
                               public_key             └──► encrypted_private_key  (guardado en DB)
                                    │
                                    └────────────────────► public_key             (guardado en DB)
```

La llave privada en texto plano existe **solo en memoria durante el registro** y nunca toca la base de datos.

### Protección de llave privada — PBKDF2 + AES-256-GCM

La llave privada se cifra antes de persistirse usando una clave derivada de la contraseña del usuario. No se usa la contraseña directamente como clave AES porque las contraseñas tienen baja entropía; en cambio se usa **PBKDF2** para derivar una clave criptográficamente fuerte:

1. **Derivación de clave:** PBKDF2-HMAC-SHA256 con salt aleatorio de 16 bytes y **310,000 iteraciones** (recomendación OWASP 2024 para PBKDF2-SHA256), produciendo una clave de 32 bytes. El salt aleatorio garantiza que dos usuarios con la misma contraseña produzcan claves derivadas distintas.
2. **Cifrado:** AES-256-GCM (cifrado autenticado AEAD), que garantiza confidencialidad e integridad del blob. El tag de autenticación de 16 bytes detecta cualquier modificación del ciphertext.
3. **Almacenamiento:** El resultado se guarda en Base64 con el formato `salt:nonce:tag:ciphertext`.

Si la contraseña es incorrecta, el tag GCM falla la verificación y el descifrado lanza una excepción.

---

## Tokens JWT

El sistema emite dos tokens al hacer login:

| Token | Expiración | Propósito |
|---|---|---|
| `access_token` | 30 minutos | Autenticar requests a endpoints protegidos |
| `refresh_token` | 7 días | Renovar el access token sin re-autenticar |

Ambos tokens se firman con **HMAC-SHA256 (HS256)** usando la `SECRET_KEY` definida en las variables de entorno. El payload incluye `sub` (user ID), `iat`, `exp` y `type`.

---

## Pruebas

Las pruebas están organizadas en dos archivos bajo `/tests`:

### `test_keys.py` — Pruebas unitarias de criptografía

Verifican el comportamiento de las funciones en `src/auth/keys.py` de forma aislada:

| Test | Qué verifica |
|---|---|
| `test_generate_rsa_keypair_returns_valid_pem` | Par RSA-2048 generado correctamente, PEM válido |
| `test_generate_ecc_keypair_returns_valid_pem` | Par ECC P-256 generado correctamente |
| `test_encrypt_and_decrypt_private_key_roundtrip` | Cifrar y descifrar produce el PEM original |
| `test_encrypted_key_has_four_parts` | El blob cifrado tiene el formato `salt:nonce:tag:ciphertext` |
| `test_decrypt_fails_with_wrong_password` | Contraseña incorrecta lanza excepción (GCM tag falla) |
| `test_each_keypair_is_unique` | Cada llamada genera un par distinto |

### `test_auth.py` — Pruebas de integración (endpoints)

Usan `TestClient` de FastAPI contra los endpoints reales con base de datos. Un fixture `registered_user` con scope `module` registra un usuario al inicio y lo elimina al final, manteniendo el entorno limpio:

| Test | Qué verifica |
|---|---|
| `test_register_creates_user_with_public_key` | Registro retorna datos correctos y llave pública PEM |
| `test_login_with_correct_credentials_returns_jwt` | Login exitoso retorna access y refresh token |
| `test_login_with_wrong_password_returns_401` | Contraseña incorrecta retorna 401 |
| `test_get_public_key_endpoint` | `GET /users/{id}/key` retorna PEM de la llave pública |
| `test_duplicate_register_returns_409` | Registrar el mismo email dos veces retorna 409 |

### Ejecutar pruebas

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

---

## Configuración

Crear un archivo `.env` basado en `.env.example`:

```
DATABASE_URL=postgresql://postgres:TU_PASSWORD@db.TU_PROYECTO.supabase.co:5432/postgres
SECRET_KEY=tu-clave-secreta-jwt
```

Aplicar la migración inicial:

```bash
psql $DATABASE_URL -f migrations/001_create_users.sql
```

Iniciar el servidor:

```bash
uvicorn main:app --reload
```

La documentación interactiva queda disponible en `http://localhost:8000/docs`.

---
## Colaboradores
- [Fabiola Contreras](https://github.com/Fabiola-cc)
- [Sofía Velásquez](https://github.com/Sofiamishel2003)
- [María José Villafuerte](https://github.com/Maria-Villafuerte)

## Referencias

- NIST SP 800-132: Recommendation for Password-Based Key Derivation
- OWASP Password Storage Cheat Sheet — iteraciones recomendadas para PBKDF2-SHA256
- RFC 5958: Asymmetric Key Packages (formato PEM)
- [pycryptodome docs](https://pycryptodome.readthedocs.io)