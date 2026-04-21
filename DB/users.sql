CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    public_key TEXT,
    encrypted_private_key TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
);