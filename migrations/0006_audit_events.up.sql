CREATE TABLE audit_events (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        REFERENCES users(id) ON DELETE SET NULL,
    event      TEXT        NOT NULL,
    reason     TEXT,
    ip         TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_events_user_id ON audit_events (user_id);
CREATE INDEX idx_audit_events_created_at ON audit_events (created_at);
