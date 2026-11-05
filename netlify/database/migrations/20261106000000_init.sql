CREATE TABLE IF NOT EXISTS users (
  id          SERIAL PRIMARY KEY,
  email       TEXT UNIQUE NOT NULL,
  name        TEXT NOT NULL,
  class       TEXT NOT NULL DEFAULT '—',
  address     TEXT NOT NULL DEFAULT '',
  gender      TEXT NOT NULL CHECK (gender IN ('boy','girl')),
  pass_hash   TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS homework (
  id          SERIAL PRIMARY KEY,
  user_id     INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title       TEXT NOT NULL,
  done        BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS notice_reads (
  user_id     INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  notice_id   INT NOT NULL,
  PRIMARY KEY (user_id, notice_id)
);
CREATE INDEX IF NOT EXISTS homework_user_idx ON homework(user_id);
