-- Add up migration script here

-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE
    "users" (
        id BIGSERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        photo VARCHAR NOT NULL DEFAULT 'default.png',
        verified BOOLEAN NOT NULL DEFAULT FALSE,
        password VARCHAR(100) NOT NULL,
        customer_name VARCHAR(100),
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        created_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT NOW()
    );

CREATE INDEX users_email_idx ON users (email);

INSERT INTO users(name, email, verified, password, role) VALUES('Simone Mazzocchi', 'simone@mazzocchinet.com', TRUE, '$argon2id$v=19$m=19456,t=2,p=1$XMPqCYO4fpsEVYYPPMmx6w$koXQpXWnGndo+sMLRf5pBYYzX6Woc9FKhxRdLHxeUWw', 'admin');

INSERT INTO users(name, email, verified, password, customer_name, role) VALUES('NCM TEST', 'ncm@mazzocchinet.com', TRUE, '$argon2id$v=19$m=19456,t=2,p=1$3Hs+AureudAukAyXExkvEw$6XYWz0T+IfoW0+OxXZykHSS3LDXLRiPoBF4FrF9pVEQ', 'N.C.M. S.P.A.' ,'user');
