"""SQLite 表结构定义。"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  path TEXT,
  kind TEXT,
  fingerprint TEXT,
  created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER,
  title TEXT,
  status TEXT DEFAULT 'open',
  risk TEXT DEFAULT '',
  category TEXT DEFAULT '',
  summary TEXT DEFAULT '',
  evidence TEXT DEFAULT '[]',
  mark TEXT DEFAULT '',
  conclusion TEXT DEFAULT '',
  ai_hint TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now','localtime')),
  updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS knowledge (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT DEFAULT '',
  title TEXT,
  pattern TEXT,
  keywords TEXT DEFAULT '',
  risk_weight REAL DEFAULT 0.5,
  source_obs INTEGER DEFAULT 0,
  enabled INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT DEFAULT (datetime('now','localtime')),
  op TEXT,
  detail TEXT,
  actor TEXT DEFAULT 'system',
  resource TEXT DEFAULT '',
  outcome TEXT DEFAULT 'success',
  risk TEXT DEFAULT 'info',
  request_id TEXT DEFAULT '',
  prev_hash TEXT DEFAULT '',
  entry_hash TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS evolve_state (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS tracking_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  exe_path TEXT DEFAULT '',
  process_name TEXT DEFAULT '',
  pid INTEGER,
  watch_paths TEXT DEFAULT '[]',
  interval_sec REAL DEFAULT 5,
  status TEXT DEFAULT 'paused',
  enabled INTEGER DEFAULT 0,
  ai_enabled INTEGER DEFAULT 0,
  checkpoint TEXT DEFAULT '{}',
  last_run_at TEXT DEFAULT '',
  next_run_at REAL DEFAULT 0,
  last_error TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now','localtime')),
  updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS tracking_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  ts TEXT DEFAULT (datetime('now','localtime')),
  type TEXT NOT NULL,
  severity TEXT DEFAULT 'info',
  source TEXT DEFAULT 'daemon',
  detail TEXT DEFAULT '',
  data TEXT DEFAULT '{}',
  fingerprint TEXT NOT NULL,
  count INTEGER DEFAULT 1,
  last_seen TEXT DEFAULT (datetime('now','localtime')),
  UNIQUE(task_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_tracking_events_task ON tracking_events(task_id, id DESC);
CREATE TABLE IF NOT EXISTS task_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  started_at TEXT DEFAULT (datetime('now','localtime')),
  finished_at TEXT DEFAULT '',
  outcome TEXT DEFAULT 'running',
  event_count INTEGER DEFAULT 0,
  error TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS daemon_leases (
  name TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  heartbeat REAL NOT NULL
);
"""
