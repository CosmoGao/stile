CREATE TABLE web_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT
);
