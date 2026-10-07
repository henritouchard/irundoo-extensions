-- Schéma v1 de la centralisatrice (story EXT-D.4, § « Stockage »).
CREATE TABLE instances (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    uai                TEXT,
    establishment_name TEXT,
    establishment_type TEXT,
    academic_zone      TEXT,
    active             INTEGER NOT NULL,
    first_seen_at      TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL,
    last_boot_id       TEXT
);

CREATE TABLE measurements (
    id                INTEGER PRIMARY KEY,
    instance_id       TEXT NOT NULL,
    extension_key     TEXT NOT NULL,
    extension_version TEXT,
    message_id        TEXT NOT NULL,
    kind              TEXT NOT NULL,
    collected_at      TEXT NOT NULL,
    received_at       TEXT NOT NULL,
    payload           TEXT NOT NULL,
    etat              TEXT NOT NULL,
    signaux           TEXT NOT NULL,
    boot_id           TEXT,
    inserted_at       TEXT NOT NULL,
    UNIQUE (instance_id, extension_key, message_id)
);
CREATE INDEX measurements_instance_received ON measurements (instance_id, received_at DESC);

CREATE TABLE releves (
    id                    INTEGER PRIMARY KEY,
    started_at            TEXT NOT NULL,
    finished_at           TEXT NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('ok', 'echec')),
    http_status           INTEGER,
    motif                 TEXT,
    instances_count       INTEGER NOT NULL,
    measurements_inserted INTEGER NOT NULL
);

CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    sub          TEXT NOT NULL,
    name         TEXT NOT NULL,
    roles        TEXT NOT NULL,
    access_token TEXT NOT NULL,
    token_exp    TEXT NOT NULL,
    scope        TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE attempts (
    id          TEXT PRIMARY KEY,
    state       TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    verifier    TEXT NOT NULL,
    prompt_none INTEGER NOT NULL,
    relance     INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);
