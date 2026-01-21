CREATE TABLE IF NOT EXISTS sales (
  day TEXT PRIMARY KEY,
  amount INTEGER NOT NULL
);

INSERT OR IGNORE INTO sales(day, amount) VALUES
('2026-01-10', 120),
('2026-01-11', 90),
('2026-01-12', 150);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL
);

INSERT OR IGNORE INTO users(id, name, email) VALUES
(1, 'Alice', 'alice@example.com'),
(2, 'Bob', 'bob@example.com');

CREATE TABLE IF NOT EXISTS api_keys (
  user_id INTEGER,
  api_key TEXT NOT NULL
);

INSERT OR IGNORE INTO api_keys(user_id, api_key) VALUES
(1, 'api_key:FAKE123456'),
(2, 'api_key:FAKE999999');