CREATE TABLE IF NOT EXISTS access_events (
  id INTEGER PRIMARY KEY,
  at INTEGER NOT NULL,
  event TEXT NOT NULL,
  path TEXT NOT NULL,
  ip TEXT,
  country TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS access_events_at ON access_events(at);
CREATE TABLE IF NOT EXISTS admission_keys (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  secret TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admission_grants (
  id INTEGER PRIMARY KEY,
  digest TEXT NOT NULL UNIQUE,
  stage TEXT NOT NULL CHECK (stage IN ('bot', 'notice', 'accepted')),
  expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS admission_expires ON admission_grants(expires);
