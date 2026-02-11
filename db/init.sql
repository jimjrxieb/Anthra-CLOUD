-- NovaSec Cloud database schema
-- Deliberately simple — no constraints, no indexes, no audit columns

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT,
    level TEXT,
    message TEXT,
    source TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT,
    title TEXT,
    body TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'viewer'
);

-- Seed demo data
INSERT INTO users (username, password_hash, role)
VALUES ('admin', md5('admin123'), 'admin')
ON CONFLICT (username) DO NOTHING;

INSERT INTO logs (tenant_id, level, message, source) VALUES
    ('tenant-1', 'INFO', 'System startup for tenant-1', 'api'),
    ('tenant-2', 'INFO', 'System startup for tenant-2', 'api'),
    ('tenant-3', 'WARN', 'High CPU usage detected', 'monitor'),
    ('tenant-1', 'ERROR', 'Failed authentication attempt', 'auth'),
    ('tenant-2', 'INFO', 'Log ingestion pipeline started', 'ingest');
