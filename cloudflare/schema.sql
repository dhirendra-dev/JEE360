CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_iterations INTEGER NOT NULL DEFAULT 310000,
  password_hash_scheme TEXT NOT NULL DEFAULT 'pbkdf2-server',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS subjects (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#7c8cf8',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(user_id, name)
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject_id TEXT REFERENCES subjects(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  due_date TEXT,
  priority TEXT NOT NULL DEFAULT 'medium' CHECK(priority IN ('low','medium','high')),
  status TEXT NOT NULL DEFAULT 'todo' CHECK(status IN ('todo','in_progress','done')),
  estimated_minutes INTEGER NOT NULL DEFAULT 30,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS tasks_user_due_idx ON tasks(user_id, due_date);
CREATE TABLE IF NOT EXISTS study_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject_id TEXT REFERENCES subjects(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  duration_minutes INTEGER NOT NULL CHECK(duration_minutes > 0),
  studied_on TEXT NOT NULL DEFAULT (date('now')),
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS study_sessions_user_date_idx ON study_sessions(user_id, studied_on);
CREATE TABLE IF NOT EXISTS user_settings (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  target_exam TEXT NOT NULL DEFAULT 'JEE Main + Advanced',
  daily_goal_minutes INTEGER NOT NULL DEFAULT 360,
  timezone TEXT NOT NULL DEFAULT 'Asia/Kolkata',
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS auth_rate_limits (
  key TEXT PRIMARY KEY,
  hits INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL
);
-- Query-path indexes and tenant-safe subject relationships.
CREATE INDEX IF NOT EXISTS sessions_user_expiry_idx ON sessions(user_id, expires_at);
CREATE INDEX IF NOT EXISTS tasks_user_status_due_idx ON tasks(user_id, status, due_date);
CREATE INDEX IF NOT EXISTS tasks_subject_user_idx ON tasks(subject_id, user_id);
CREATE INDEX IF NOT EXISTS study_sessions_user_date_subject_idx ON study_sessions(user_id, studied_on, subject_id);
CREATE INDEX IF NOT EXISTS study_sessions_subject_user_idx ON study_sessions(subject_id, user_id);
CREATE INDEX IF NOT EXISTS auth_rate_limits_window_idx ON auth_rate_limits(window_start);
CREATE UNIQUE INDEX IF NOT EXISTS subjects_user_name_nocase_idx ON subjects(user_id, name COLLATE NOCASE);

-- The API checks ownership too; these triggers make the database enforce it
-- even if a future endpoint forgets the user-scoped lookup.
CREATE TRIGGER IF NOT EXISTS tasks_subject_owner_insert
BEFORE INSERT ON tasks
WHEN NEW.subject_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM subjects WHERE id = NEW.subject_id AND user_id = NEW.user_id)
BEGIN
  SELECT RAISE(ABORT, 'task subject must belong to the same user');
END;

CREATE TRIGGER IF NOT EXISTS tasks_subject_owner_update
BEFORE UPDATE OF user_id, subject_id ON tasks
WHEN NEW.subject_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM subjects WHERE id = NEW.subject_id AND user_id = NEW.user_id)
BEGIN
  SELECT RAISE(ABORT, 'task subject must belong to the same user');
END;

CREATE TRIGGER IF NOT EXISTS study_sessions_subject_owner_insert
BEFORE INSERT ON study_sessions
WHEN NEW.subject_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM subjects WHERE id = NEW.subject_id AND user_id = NEW.user_id)
BEGIN
  SELECT RAISE(ABORT, 'study subject must belong to the same user');
END;

CREATE TRIGGER IF NOT EXISTS study_sessions_subject_owner_update
BEFORE UPDATE OF user_id, subject_id ON study_sessions
WHEN NEW.subject_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM subjects WHERE id = NEW.subject_id AND user_id = NEW.user_id)
BEGIN
  SELECT RAISE(ABORT, 'study subject must belong to the same user');
END;

CREATE TRIGGER IF NOT EXISTS tasks_minutes_insert
BEFORE INSERT ON tasks
WHEN NEW.estimated_minutes < 5 OR NEW.estimated_minutes > 1440
BEGIN
  SELECT RAISE(ABORT, 'estimated_minutes must be between 5 and 1440');
END;

CREATE TRIGGER IF NOT EXISTS tasks_minutes_update
BEFORE UPDATE OF estimated_minutes ON tasks
WHEN NEW.estimated_minutes < 5 OR NEW.estimated_minutes > 1440
BEGIN
  SELECT RAISE(ABORT, 'estimated_minutes must be between 5 and 1440');
END;

CREATE TRIGGER IF NOT EXISTS study_duration_insert
BEFORE INSERT ON study_sessions
WHEN NEW.duration_minutes < 1 OR NEW.duration_minutes > 1440
BEGIN
  SELECT RAISE(ABORT, 'duration_minutes must be between 1 and 1440');
END;

CREATE TRIGGER IF NOT EXISTS study_duration_update
BEFORE UPDATE OF duration_minutes ON study_sessions
WHEN NEW.duration_minutes < 1 OR NEW.duration_minutes > 1440
BEGIN
  SELECT RAISE(ABORT, 'duration_minutes must be between 1 and 1440');
END;

CREATE TRIGGER IF NOT EXISTS user_settings_goal_insert
BEFORE INSERT ON user_settings
WHEN NEW.daily_goal_minutes < 30 OR NEW.daily_goal_minutes > 1440
BEGIN
  SELECT RAISE(ABORT, 'daily_goal_minutes must be between 30 and 1440');
END;

CREATE TRIGGER IF NOT EXISTS user_settings_goal_update
BEFORE UPDATE OF daily_goal_minutes ON user_settings
WHEN NEW.daily_goal_minutes < 30 OR NEW.daily_goal_minutes > 1440
BEGIN
  SELECT RAISE(ABORT, 'daily_goal_minutes must be between 30 and 1440');
END;
