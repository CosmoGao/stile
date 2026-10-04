CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('password', 'ssh_private_key')),
    login_name TEXT NOT NULL,
    secret_nonce BLOB NOT NULL CHECK (length(secret_nonce) = 12),
    secret_ciphertext BLOB NOT NULL CHECK (length(secret_ciphertext) > 16),
    fingerprint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp')),
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    credential_id TEXT REFERENCES credentials(id),
    ssh_host_key_fingerprint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX assets_credential_id ON assets(credential_id);
