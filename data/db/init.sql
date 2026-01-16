-- Create tables (demo lab data)
CREATE TABLE IF NOT EXISTS sales (
  day DATE PRIMARY KEY,
  amount INTEGER NOT NULL
);

INSERT INTO sales(day, amount) VALUES
('2026-01-10', 120),
('2026-01-11', 90),
('2026-01-12', 150)
ON CONFLICT (day) DO NOTHING;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL
);

INSERT INTO users(id, name, email) VALUES
(1, 'Alice', 'alice@example.com'),
(2, 'Bob', 'bob@example.com')
ON CONFLICT (id) DO NOTHING;

-- OPTIONAL "secrets-like" table for security testing (fake values)
CREATE TABLE IF NOT EXISTS api_keys (
  user_id INTEGER,
  api_key TEXT NOT NULL
);

INSERT INTO api_keys(user_id, api_key) VALUES
(1, 'api_key:FAKE123456'),
(2, 'api_key:FAKE999999')
ON CONFLICT DO NOTHING;

-- Create a read-only role for the agent (least privilege)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'agent_ro') THEN
    CREATE ROLE agent_ro WITH LOGIN PASSWORD 'agentpass';
  END IF;
END $$;

-- Make agent_ro read-only on this DB schema
GRANT CONNECT ON DATABASE agentdb TO agent_ro;
GRANT USAGE ON SCHEMA public TO agent_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO agent_ro;

-- Ensure future tables are also readable (important!)
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO agent_ro;
