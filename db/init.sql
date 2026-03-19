-- Anthra Security Platform — PostgreSQL schema
-- Tenant isolation enforced at query level; indexes support filtered queries

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'viewer',
    tenant_id TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT,
    source TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_logs_tenant ON logs (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);

-- Seed demo user — password: Change-Me-1!
-- bcrypt hash generated offline; replace in production via secrets manager
INSERT INTO users (username, password_hash, email, role, tenant_id)
VALUES (
    'admin',
    '$2b$12$DESbgG62X.tb0rSTKln9P.EmK3jt1hecrfBlYRLbWGtoEnTE01Uaa',
    'admin@anthra.io',
    'admin',
    'tenant-1'
) ON CONFLICT (username) DO NOTHING;

-- Seed demo logs
INSERT INTO logs (tenant_id, level, message, source) VALUES
    ('tenant-1', 'INFO', 'System startup for tenant-1', 'api'),
    ('tenant-2', 'INFO', 'System startup for tenant-2', 'api'),
    ('tenant-3', 'WARN', 'High CPU usage detected', 'monitor'),
    ('tenant-1', 'ERROR', 'Failed authentication attempt', 'auth'),
    ('tenant-2', 'INFO', 'Log ingestion pipeline started', 'ingest');
