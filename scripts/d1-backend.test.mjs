import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const schema = await readFile(new URL("../cloudflare/schema.sql", import.meta.url), "utf8");
const worker = await readFile(new URL("../cloudflare/worker.js", import.meta.url), "utf8");

test("D1 schema has query indexes and case-insensitive subject uniqueness", () => {
  for (const name of [
    "sessions_user_expiry_idx",
    "tasks_user_status_due_idx",
    "study_sessions_user_date_subject_idx",
    "auth_rate_limits_window_idx",
    "subjects_user_name_nocase_idx",
  ]) assert.match(schema, new RegExp(name));
});

test("D1 enforces per-user subject ownership at the database layer", () => {
  for (const name of [
    "tasks_subject_owner_insert",
    "tasks_subject_owner_update",
    "study_sessions_subject_owner_insert",
    "study_sessions_subject_owner_update",
  ]) assert.match(schema, new RegExp(name));
});

test("health check probes real tables instead of SQLite internal catalog", () => {
  assert.doesNotMatch(worker, /FROM sqlite_master/i);
  assert.match(worker, /SELECT 1 FROM auth_rate_limits LIMIT 0/);
  assert.match(worker, /schema_version: 1/);
});

test("auth rate limiting and expired-record cleanup are committed as one D1 batch", () => {
  assert.match(worker, /env\.DB\.batch\(\[/);
  assert.match(worker, /DELETE FROM auth_rate_limits WHERE window_start < \?/);
  assert.match(worker, /DELETE FROM sessions WHERE expires_at <= \?/);
});

test("settings updates preserve fields omitted from a PATCH request", () => {
  assert.match(worker, /updates\.push\("daily_goal_minutes=excluded\.daily_goal_minutes"\)/);
  assert.match(worker, /updates\.push\("target_exam=excluded\.target_exam"\)/);
  assert.match(worker, /updates\.push\("timezone=excluded\.timezone"\)/);
});

test("D1 foreign keys rely on the platform's enforced default", async () => {
  const migration = await readFile(new URL("../cloudflare/migrations/0001_initial_schema.sql", import.meta.url), "utf8");
  assert.doesNotMatch(schema, /PRAGMA foreign_keys/i);
  assert.doesNotMatch(migration, /PRAGMA foreign_keys/i);
  assert.match(schema, /REFERENCES users\(id\) ON DELETE CASCADE/);
});
