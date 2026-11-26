const COOKIE = "jee360_session";
const SESSION_DAYS = 30;
const ITERATIONS = 310000;
const encoder = new TextEncoder();

function json(data, status, headers) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: Object.assign({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }, headers || {}) });
}
function randomHex(bytes) {
  const a = new Uint8Array(bytes); crypto.getRandomValues(a);
  return Array.from(a).map(function(x) { return x.toString(16).padStart(2, "0"); }).join("");
}
async function digest(value) {
  const b = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(b)).map(function(x) { return x.toString(16).padStart(2, "0"); }).join("");
}
async function passwordHash(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: encoder.encode(salt), iterations: iterations, hash: "SHA-256" }, key, 256);
  return Array.from(new Uint8Array(bits)).map(function(x) { return x.toString(16).padStart(2, "0"); }).join("");
}
function cookie(value, maxAge) {
  return COOKIE + "=" + value + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + maxAge;
}
function clearCookie() { return COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"; }
function getCookie(request) {
  const raw = request.headers.get("Cookie") || "";
  const part = raw.split(";").map(function(x) { return x.trim(); }).find(function(x) { return x.indexOf(COOKIE + "=") === 0; });
  return part ? part.slice(COOKIE.length + 1) : "";
}
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254; }
function validDate(value) {
  if (value == null || value === "") return true;
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(value + "T00:00:00Z");
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}
function validTimezone(value) {
  if (typeof value !== "string" || !value || value.length > 80) return false;
  try { new Intl.DateTimeFormat("en-US", { timeZone: value }); return true; } catch (_) { return false; }
}
function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function body(request) {
  try { return await request.json(); } catch (_) { return null; }
}
function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  const url = new URL(request.url);
  if (origin) return origin === url.origin;
  if (request.method === "GET" || request.method === "HEAD") return true;
  return request.headers.get("Sec-Fetch-Site") === "same-origin";
}
async function userFor(request, env) {
  const token = getCookie(request);
  if (!token) return null;
  const hash = await digest(token);
  const row = await env.DB.prepare("SELECT u.id,u.email,u.display_name,u.created_at,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(hash, new Date().toISOString()).first();
  return row || null;
}
async function rateLimited(request, env, action, limit, windowSeconds) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const key = await digest(ip + ":" + action);
  const now = Math.floor(Date.now() / 1000);
  const cutoff = now - windowSeconds;
  await env.DB.batch([
    env.DB.prepare("INSERT INTO auth_rate_limits (key,hits,window_start) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET hits=CASE WHEN window_start<=? THEN 1 ELSE hits+1 END,window_start=CASE WHEN window_start<=? THEN excluded.window_start ELSE window_start END").bind(key, now, cutoff, cutoff),
    env.DB.prepare("DELETE FROM auth_rate_limits WHERE window_start < ?").bind(now - 86400),
    env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(new Date(now * 1000).toISOString())
  ]);
  const row = await env.DB.prepare("SELECT hits FROM auth_rate_limits WHERE key=?").bind(key).first();
  return Number(row && row.hits) > limit;
}
async function createSession(userId, env) {
  const token = randomHex(32);
  const hash = await digest(token);
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  await env.DB.prepare("INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)").bind(crypto.randomUUID(), userId, hash, expires).run();
  return token;
}
async function requireUser(request, env) {
  const user = await userFor(request, env);
  if (!user) return { error: json({ error: "Please sign in to continue." }, 401) };
  return { user: user };
}
async function handleApi(request, env, path) {
  if (!sameOrigin(request)) return json({ error: "Cross-origin request blocked." }, 403);
  const method = request.method;
  if (path === "/api/health" && method === "GET") {
    await env.DB.batch([
      env.DB.prepare("SELECT 1 FROM users LIMIT 0"),
      env.DB.prepare("SELECT 1 FROM sessions LIMIT 0"),
      env.DB.prepare("SELECT 1 FROM tasks LIMIT 0"),
      env.DB.prepare("SELECT 1 FROM subjects LIMIT 0"),
      env.DB.prepare("SELECT 1 FROM study_sessions LIMIT 0"),
      env.DB.prepare("SELECT 1 FROM user_settings LIMIT 0"),
      env.DB.prepare("SELECT 1 FROM auth_rate_limits LIMIT 0")
    ]);
    return json({ ok: true, service: "JEE360", database: "connected", schema_version: 1 });
  }
  if (path === "/api/auth/register" && method === "POST") {
    const data = await body(request);
    if (!data || typeof data.email !== "string" || typeof data.password !== "string" || typeof data.name !== "string") return json({ error: "Please provide your name, email and password." }, 400);
    const email = data.email.trim().toLowerCase();
    const name = data.name.trim().slice(0, 60);
    if (!name || !validEmail(email)) return json({ error: "Enter a valid name and email address." }, 400);
    if (data.password.length < 10 || data.password.length > 128) return json({ error: "Use a password between 10 and 128 characters." }, 400);
    if (await rateLimited(request, env, "register", 12, 900)) return json({ error: "Too many sign-up attempts from this connection. Please wait 15 minutes, then try again." }, 429);
    const id = crypto.randomUUID();
    const salt = randomHex(16);
    const hash = await passwordHash(data.password, salt, ITERATIONS);
    const token = randomHex(32);
    const tokenHash = await digest(token);
    const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users (id,email,display_name,password_salt,password_hash,password_iterations) VALUES (?,?,?,?,?,?)").bind(id, email, name, salt, hash, ITERATIONS),
        env.DB.prepare("INSERT INTO user_settings (user_id) VALUES (?)").bind(id),
        env.DB.prepare("INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)").bind(crypto.randomUUID(), id, tokenHash, expires)
      ]);
    } catch (error) {
      const message = String(error && error.message || "");
      if (/unique constraint|already exists/i.test(message)) return json({ error: "An account with this email already exists. Please sign in instead." }, 409);
      console.error("JEE360 registration transaction failed", error);
      return json({ error: "We couldn't finish creating your account. Please try again in a moment." }, 500);
    }
    return json({ user: { id: id, email: email, display_name: name } }, 201, { "set-cookie": cookie(token, SESSION_DAYS * 86400) });
  }
  if (path === "/api/auth/login" && method === "POST") {
    const data = await body(request);
    if (!data || typeof data.email !== "string" || typeof data.password !== "string") return json({ error: "Enter your email and password." }, 400);
    const email = data.email.trim().toLowerCase();
    if (await rateLimited(request, env, "login", 12, 900)) return json({ error: "Too many sign-in attempts. Please wait 15 minutes." }, 429);
    const row = await env.DB.prepare("SELECT id,email,display_name,password_salt,password_hash,password_iterations FROM users WHERE email=?").bind(email).first();
    const salt = row ? row.password_salt : "jee360-invalid-user-salt";
    const expected = row ? row.password_hash : "not-a-valid-password-hash";
    const actual = await passwordHash(data.password.slice(0, 128), salt, row ? Number(row.password_iterations) : ITERATIONS);
    if (!row || !constantTimeEqual(actual, expected)) return json({ error: "Email or password is incorrect." }, 401);
    const token = await createSession(row.id, env);
    return json({ user: { id: row.id, email: row.email, display_name: row.display_name } }, 200, { "set-cookie": cookie(token, SESSION_DAYS * 86400) });
  }
  if (path === "/api/auth/logout" && method === "POST") {
    const token = getCookie(request);
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return json({ ok: true }, 200, { "set-cookie": clearCookie() });
  }
  if (path === "/api/auth/me" && method === "GET") {
    const user = await userFor(request, env);
    if (!user) return json({ user: null });
    return json({ user: { id: user.id, email: user.email, display_name: user.display_name } });
  }
  const auth = await requireUser(request, env);
  if (!auth.user) return auth.error;
  const userId = auth.user.id;

  if (path === "/api/auth/password" && method === "POST") {
    const data = await body(request);
    if (!data || typeof data.current_password !== "string" || typeof data.new_password !== "string") return json({ error: "Enter your current and new passwords." }, 400);
    if (data.new_password.length < 10 || data.new_password.length > 128) return json({ error: "Use a new password between 10 and 128 characters." }, 400);
    if (await rateLimited(request, env, "password-change", 5, 3600)) return json({ error: "Too many password-change attempts. Try again later." }, 429);
    const account = await env.DB.prepare("SELECT password_salt,password_hash,password_iterations FROM users WHERE id=?").bind(userId).first();
    if (!account) return json({ error: "Account not found." }, 404);
    const currentHash = await passwordHash(data.current_password.slice(0, 128), account.password_salt, Number(account.password_iterations));
    if (!constantTimeEqual(currentHash, account.password_hash)) return json({ error: "Your current password is incorrect." }, 401);
    const salt = randomHex(16);
    const hash = await passwordHash(data.new_password, salt, ITERATIONS);
    const token = randomHex(32);
    const tokenHash = await digest(token);
    const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET password_salt=?,password_hash=?,password_iterations=?,updated_at=datetime('now') WHERE id=?").bind(salt, hash, ITERATIONS, userId),
      env.DB.prepare("INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)").bind(crypto.randomUUID(), userId, tokenHash, expires),
      env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND token_hash<>?").bind(userId, tokenHash)
    ]);
    return json({ ok: true }, 200, { "set-cookie": cookie(token, SESSION_DAYS * 86400) });
  }
  if (path === "/api/dashboard" && method === "GET") {
    const todayLocal = new Intl.DateTimeFormat("en-CA", {timeZone:"Asia/Kolkata",year:"numeric",month:"2-digit",day:"2-digit"}).format(new Date());
    const shiftDate = function(value, amount) {
      const date = new Date(value + "T00:00:00Z");
      date.setUTCDate(date.getUTCDate() + amount);
      return date.toISOString().slice(0, 10);
    };
    const weekStart = shiftDate(todayLocal, -6);
    const streakStart = shiftDate(todayLocal, -364);
    const results = await Promise.all([
      env.DB.prepare("SELECT id,title,description,due_date,priority,status,estimated_minutes,subject_id,created_at FROM tasks WHERE user_id=? ORDER BY CASE status WHEN 'in_progress' THEN 0 WHEN 'todo' THEN 1 ELSE 2 END, due_date IS NULL, due_date LIMIT 100").bind(userId).all(),
      env.DB.prepare("SELECT id,name,color FROM subjects WHERE user_id=? ORDER BY name").bind(userId).all(),
      env.DB.prepare("SELECT COALESCE(SUM(duration_minutes),0) AS total FROM study_sessions WHERE user_id=? AND studied_on=?").bind(userId, todayLocal).first(),
      env.DB.prepare("SELECT COUNT(*) AS completed FROM tasks WHERE user_id=? AND status='done'").bind(userId).first(),
      env.DB.prepare("SELECT target_exam,daily_goal_minutes,timezone FROM user_settings WHERE user_id=?").bind(userId).first(),
      env.DB.prepare("SELECT studied_on,COALESCE(SUM(duration_minutes),0) AS total FROM study_sessions WHERE user_id=? AND studied_on BETWEEN ? AND ? GROUP BY studied_on ORDER BY studied_on").bind(userId, weekStart, todayLocal).all(),
      env.DB.prepare("SELECT DISTINCT studied_on FROM study_sessions WHERE user_id=? AND studied_on BETWEEN ? AND ? ORDER BY studied_on DESC").bind(userId, streakStart, todayLocal).all(),
      env.DB.prepare("SELECT COALESCE(SUM(duration_minutes),0) AS total FROM study_sessions WHERE user_id=?").bind(userId).first()
    ]);
    const studyDates = new Set(results[6].results.map(function(row) { return row.studied_on; }));
    let streakCursor = studyDates.has(todayLocal) ? todayLocal : shiftDate(todayLocal, -1);
    let streakDays = 0;
    while (studyDates.has(streakCursor) && streakDays < 365) {
      streakDays += 1;
      streakCursor = shiftDate(streakCursor, -1);
    }
    const weeklyMinutes = [];
    for (let offset = 0; offset < 7; offset++) {
      const date = shiftDate(weekStart, offset);
      const row = results[5].results.find(function(item) { return item.studied_on === date; });
      weeklyMinutes.push({ date: date, minutes: Number(row ? row.total : 0) });
    }
    return json({
      tasks: results[0].results,
      subjects: results[1].results,
      today_minutes: results[2].total,
      completed: results[3].completed,
      settings: results[4] || { target_exam: "JEE Main + Advanced", daily_goal_minutes: 360, timezone: "Asia/Kolkata" },
      weekly_minutes: weeklyMinutes,
      streak_days: streakDays,
      all_time_minutes: results[7].total
    });
  }
  if (path === "/api/tasks" && method === "POST") {
    const data = await body(request);
    if (!data || typeof data.title !== "string" || !data.title.trim()) return json({ error: "Task title is required." }, 400);
    const priority = ["low","medium","high"].includes(data.priority) ? data.priority : "medium";
    const status = ["todo","in_progress","done"].includes(data.status) ? data.status : "todo";
    const mins = data.estimated_minutes == null || data.estimated_minutes === "" ? 30 : Number(data.estimated_minutes);
    if (!Number.isInteger(mins) || mins < 5 || mins > 1440) return json({ error: "Estimated time must be between 5 and 1,440 whole minutes." }, 400);
    const dueDate = data.due_date == null || data.due_date === "" ? null : data.due_date;
    if (!validDate(dueDate)) return json({ error: "Enter a valid due date." }, 400);
    if (data.subject_id != null && data.subject_id !== "" && typeof data.subject_id !== "string") return json({ error: "Choose a valid subject." }, 400);
    const id = crypto.randomUUID();
    const subjectId = typeof data.subject_id === "string" && data.subject_id ? data.subject_id : null;
    if (subjectId) {
      const s = await env.DB.prepare("SELECT id FROM subjects WHERE id=? AND user_id=?").bind(subjectId,userId).first();
      if (!s) return json({ error: "Subject not found." }, 404);
    }
    await env.DB.prepare("INSERT INTO tasks (id,user_id,subject_id,title,description,due_date,priority,status,estimated_minutes) VALUES (?,?,?,?,?,?,?,?,?)").bind(id,userId,subjectId,data.title.trim().slice(0,140),String(data.description || "").slice(0,1000),dueDate,priority,status,mins).run();
    return json({ id: id }, 201);
  }
  const taskMatch = path.match(/^\/api\/tasks\/([a-f0-9-]+)$/i);
  if (taskMatch && method === "PATCH") {
    const data = (await body(request)) || {};
    const id = taskMatch[1];
    const task = await env.DB.prepare("SELECT id FROM tasks WHERE id=? AND user_id=?").bind(id,userId).first();
    if (!task) return json({ error: "Task not found." }, 404);
    const allowed = {};
    if (["todo","in_progress","done"].includes(data.status)) allowed.status = data.status;
    if (["low","medium","high"].includes(data.priority)) allowed.priority = data.priority;
    if (typeof data.title === "string" && data.title.trim()) allowed.title = data.title.trim().slice(0,140);
    if (Object.keys(allowed).length) {
      const keys = Object.keys(allowed);
      const sql = "UPDATE tasks SET " + keys.map(function(k) { return k + "=?"; }).join(",") + ",updated_at=datetime('now') WHERE id=? AND user_id=?";
      const statement = env.DB.prepare(sql);
      await statement.bind.apply(statement, keys.map(function(k) { return allowed[k]; }).concat([id,userId])).run();
    }
    return json({ ok: true });
  }
  if (taskMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM tasks WHERE id=? AND user_id=?").bind(taskMatch[1],userId).run();
    return json({ ok: true });
  }
  if (path === "/api/subjects" && method === "POST") {
    const data = await body(request);
    if (!data || typeof data.name !== "string" || !data.name.trim()) return json({ error: "Subject name is required." }, 400);
    const id = crypto.randomUUID();
    try {
      await env.DB.prepare("INSERT INTO subjects (id,user_id,name,color) VALUES (?,?,?,?)").bind(id,userId,data.name.trim().slice(0,50),/^#[0-9a-f]{6}$/i.test(data.color || "") ? data.color : "#7c8cf8").run();
    } catch (error) {
      const message = String(error && error.message || "");
      if (/unique constraint|already exists/i.test(message)) return json({ error: "That subject already exists." }, 409);
      console.error("JEE360 subject insert failed", error);
      return json({ error: "We couldn't save that subject. Please try again." }, 500);
    }
    return json({ id: id }, 201);
  }
  if (path === "/api/study-sessions" && method === "POST") {
    const data = (await body(request)) || {};
    const minutes = Number(data.duration_minutes);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) return json({ error: "Study duration must be between 1 and 1,440 whole minutes." }, 400);
    if (data.subject_id != null && data.subject_id !== "" && typeof data.subject_id !== "string") return json({ error: "Choose a valid subject." }, 400);
    const subjectId = typeof data.subject_id === "string" && data.subject_id ? data.subject_id : null;
    if (subjectId) {
      const s = await env.DB.prepare("SELECT id FROM subjects WHERE id=? AND user_id=?").bind(subjectId,userId).first();
      if (!s) return json({ error: "Subject not found." }, 404);
    }
    await env.DB.prepare("INSERT INTO study_sessions (id,user_id,subject_id,title,duration_minutes,studied_on,notes) VALUES (?,?,?,?,?,?,?)").bind(crypto.randomUUID(),userId,subjectId,String(data.title || "Study session").slice(0,120),minutes,new Intl.DateTimeFormat("en-CA", {timeZone:"Asia/Kolkata",year:"numeric",month:"2-digit",day:"2-digit"}).format(new Date()),String(data.notes || "").slice(0,500)).run();
    return json({ ok: true }, 201);
  }
  if (path === "/api/settings" && method === "PATCH") {
    const data = (await body(request)) || {};
    const goal = Math.max(30,Math.min(1440,Number(data.daily_goal_minutes) || 360));
    const updates = [];
    let targetExam = "JEE Main + Advanced";
    let goal = 360;
    let timezone = "Asia/Kolkata";
    if (Object.prototype.hasOwnProperty.call(data, "target_exam")) {
      if (typeof data.target_exam !== "string" || !data.target_exam.trim() || data.target_exam.length > 80) return json({ error: "Enter a valid target exam." }, 400);
      targetExam = data.target_exam.trim(); updates.push("target_exam=excluded.target_exam");
    }
    if (Object.prototype.hasOwnProperty.call(data, "daily_goal_minutes")) {
      goal = Number(data.daily_goal_minutes);
      if (!Number.isInteger(goal) || goal < 30 || goal > 1440) return json({ error: "Daily goal must be between 30 and 1,440 whole minutes." }, 400);
      updates.push("daily_goal_minutes=excluded.daily_goal_minutes");
    }
    if (Object.prototype.hasOwnProperty.call(data, "timezone")) {
      timezone = data.timezone;
      if (!validTimezone(timezone)) return json({ error: "Choose a valid time zone." }, 400);
      updates.push("timezone=excluded.timezone");
    }
    const sql = "INSERT INTO user_settings (user_id,target_exam,daily_goal_minutes,timezone,updated_at) VALUES (?,?,?,?,datetime('now')) ON CONFLICT(user_id) DO UPDATE SET " + (updates.length ? updates.join(",") + "," : "") + "updated_at=datetime('now')";
    await env.DB.prepare(sql).bind(userId,targetExam,goal,timezone).run();
    return json({ ok: true });
  }
  return json({ error: "Not found." }, 404);
}

const PAGE = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#5878b7"><link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 40 40%22%3E%3Crect width=%2240%22 height=%2240%22 rx=%2212%22 fill=%22%235878b7%22/%3E%3Ccircle cx=%2220%22 cy=%2220%22 r=%2214%22 fill=%22none%22 stroke=%22white%22 stroke-width=%222%22/%3E%3Cpath d=%22m13 26 5-12 3 8 6-7%22 fill=%22none%22 stroke=%22white%22 stroke-width=%222.7%22 stroke-linecap=%22round%22 stroke-linejoin=%22round%22/%3E%3C/svg%3E"><title>JEE360 — Your preparation, in focus</title>
<style>
:root{color-scheme:light;--bg:#f4f3ee;--surface:#fffefa;--surface-soft:#f8f8f4;--surface-blue:#edf2fb;--line:#e1e5ec;--line-strong:#d1d9e5;--text:#253247;--muted:#778398;--blue:#5878b7;--blue-strong:#4567a8;--blue-soft:#e7edf8;--cyan:#5d9caa;--good:#397e68;--warn:#a77a35;--red:#b95b68;--shadow:0 8px 24px rgba(44,61,88,.055);--focus:rgba(88,120,183,.2)}
:root[data-theme="dark"]{color-scheme:dark;--bg:#111824;--surface:#192333;--surface-soft:#1d2a3d;--surface-blue:#202f46;--line:#2b3a50;--line-strong:#3b4b63;--text:#e9eef6;--muted:#9aa8bb;--blue:#9ab3e8;--blue-strong:#b1c6f1;--blue-soft:#263753;--cyan:#8bc4cf;--good:#83c4a9;--warn:#e2bd78;--red:#ee9aa5;--shadow:0 12px 32px rgba(0,0,0,.18);--focus:rgba(154,179,232,.2)}
*{box-sizing:border-box}html{min-height:100%;background:var(--bg)}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh;transition:background .2s ease,color .2s ease}button,input,select,textarea{font:inherit}button{cursor:pointer}.hidden{display:none!important}.muted{color:var(--muted)}
.app{max-width:1180px;margin:0 auto;padding:28px 32px 36px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;padding-bottom:18px;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:11px}.logo{width:42px;height:42px;flex:0 0 42px;border-radius:13px;background:var(--blue);display:grid;place-items:center;color:#fff;box-shadow:0 3px 8px rgba(55,82,132,.16);overflow:hidden}.logo svg{display:block;width:30px;height:30px}.brand h1{font-size:17px;margin:0;font-weight:750;letter-spacing:-.35px}.brand small{display:block;color:var(--muted);font-size:10px;letter-spacing:1.35px;text-transform:uppercase;margin-top:1px}.topright{display:flex;align-items:center;gap:9px}.pill{border:1px solid var(--line);background:var(--surface);padding:7px 11px;border-radius:9px;color:var(--muted);font-size:12px}
.btn{border:1px solid var(--blue);border-radius:9px;padding:9px 14px;background:var(--blue);color:#fff;font-weight:650;transition:background .16s,border-color .16s,transform .16s}.btn:hover{background:var(--blue-strong);border-color:var(--blue-strong)}.btn:active{transform:translateY(1px)}.btn.secondary{background:var(--surface-blue);color:var(--blue-strong);border:1px solid var(--line-strong)}.btn.secondary:hover{background:var(--blue-soft)}.btn.ghost{background:transparent;color:var(--muted);border:1px solid var(--line)}.btn.ghost:hover{background:var(--surface-soft);color:var(--text)}.btn.danger{background:#f7e9eb;color:#9b4350;border:1px solid #e9cbd0}.theme-toggle{display:inline-flex;align-items:center;gap:7px;padding:8px 11px;border:1px solid var(--line);border-radius:9px;background:var(--surface);color:var(--muted);font-size:12px;font-weight:600}.theme-toggle:hover{color:var(--text);background:var(--surface-soft)}.theme-symbol{font-size:15px;line-height:1}
.hero{display:flex;justify-content:space-between;align-items:end;gap:18px;margin:29px 0 20px}.eyebrow{color:var(--blue);font-size:10px;font-weight:750;letter-spacing:1.55px;text-transform:uppercase}.hero h2{font-size:clamp(26px,4vw,34px);letter-spacing:-1.1px;line-height:1.16;margin:7px 0 5px;font-weight:720}.hero p{margin:0;color:var(--muted);font-size:14px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:var(--shadow)}.stat-label{font-size:12px;color:var(--muted);font-weight:550}.stat{font-size:28px;font-weight:750;letter-spacing:-.8px;margin:8px 0 1px;color:var(--text)}.stat-sub{font-size:11px;color:var(--muted)}
.layout{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(270px,.8fr);gap:14px;margin-top:14px}.section-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:14px}.section-head h3{margin:0;font-size:15px;font-weight:700;letter-spacing:-.2px}.task-list{display:grid;gap:8px}.task{display:flex;align-items:center;gap:11px;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--surface-soft)}.check{width:20px;height:20px;border:1.5px solid var(--line-strong);border-radius:6px;background:var(--surface);flex:none;color:white}.task-main{min-width:0;flex:1}.task-title{font-weight:620;overflow-wrap:anywhere;font-size:13px}.task.done .task-title{text-decoration:line-through;color:var(--muted)}.task-meta{font-size:11px;color:var(--muted);margin-top:3px}.priority{font-size:10px;border-radius:6px;padding:4px 7px;background:var(--surface-blue);color:var(--blue-strong);font-weight:650}.priority.high{background:#f7e9eb;color:#a64e5a}.priority.low{background:#e8f2ed;color:#397e68}.progress{height:6px;background:var(--surface-blue);border-radius:99px;overflow:hidden;margin:12px 0}.progress span{display:block;height:100%;background:var(--blue);border-radius:99px;transition:width .25s}
.formrow{display:flex;gap:8px}.field{width:100%;border:1px solid var(--line-strong);background:var(--surface);color:var(--text);border-radius:9px;padding:10px 11px;outline:none;transition:border-color .15s,box-shadow .15s}.field:focus{border-color:var(--blue);box-shadow:0 0 0 3px var(--focus)}.field::placeholder{color:var(--muted)}label{display:block;font-size:12px;color:var(--muted);font-weight:600;margin:12px 0 6px}.stack{display:grid;gap:10px}.subject{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--line);font-size:13px}.dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:9px}
.modal{position:fixed;inset:0;background:rgba(18,28,43,.48);display:grid;place-items:center;padding:16px;z-index:5;backdrop-filter:blur(3px)}.modalbox{width:min(440px,100%);background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:23px;box-shadow:0 22px 70px rgba(20,35,55,.2)}.modalbox h2{margin:0 0 4px}.authwrap{min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg)}.authcard{width:min(430px,100%);padding:30px}.authcard h2{font-size:27px;letter-spacing:-.8px;margin:0 0 4px}.authbrand{display:flex;justify-content:space-between;align-items:center;margin-bottom:28px}.notice{font-size:12px;color:var(--muted);margin-top:15px}.error-text{color:var(--red);font-weight:650}.btn:disabled{opacity:.65;cursor:wait;transform:none}.empty{padding:24px;text-align:center;color:var(--muted);border:1px dashed var(--line-strong);border-radius:10px;background:var(--surface-soft)}.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);padding:10px 15px;border-radius:9px;background:var(--text);color:var(--bg);font-weight:650;font-size:13px;z-index:10;box-shadow:var(--shadow)}.foot{padding:22px 0;color:var(--muted);text-align:center;font-size:11px}
@media(max-width:850px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.layout{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}.app{padding:20px}}@media(max-width:520px){.app{padding:15px 13px 26px}.top{align-items:flex-start}.topright{gap:6px;flex-wrap:wrap;justify-content:flex-end}.topright .pill{display:none}.theme-toggle{padding:7px 9px}.theme-toggle .theme-label{display:none}.grid{gap:8px}.card{padding:14px;border-radius:12px}.stat{font-size:24px}.formrow{flex-wrap:wrap}.hero h2{font-size:27px}.task{gap:8px;padding:10px}.priority{display:none}.authcard{padding:22px}.authbrand{margin-bottom:22px}}@media(prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;scroll-behavior:auto!important}}

.grid{grid-template-columns:repeat(5,minmax(0,1fr))}
.feature-row{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(290px,1fr);gap:12px;margin:14px 0 16px}
.insight-card,.timer-card{min-width:0}
.week-bars{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:10px;align-items:end;height:132px;padding:10px 2px 0}
.week-col{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:7px;min-width:0;height:100%}
.week-value{font-size:10px;color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums}
.week-track{height:82px;width:min(100%,34px);display:flex;align-items:flex-end;background:var(--surface-soft);border-radius:8px 8px 5px 5px;overflow:hidden}
.week-fill{display:block;width:100%;min-height:3px;background:linear-gradient(180deg,var(--cyan),var(--blue));border-radius:7px 7px 4px 4px;transition:height .75s cubic-bezier(.2,.8,.2,1)}
.week-day{font-size:10px;color:var(--muted)}
.week-summary{display:flex;gap:18px;flex-wrap:wrap;padding-top:13px;border-top:1px solid var(--line);margin-top:8px}
.week-summary strong{display:block;font-size:17px;letter-spacing:-.4px}
.week-summary span{font-size:11px;color:var(--muted)}
.focus-layout{display:grid;grid-template-columns:132px minmax(0,1fr);align-items:center;gap:15px;margin-top:10px}
.timer-ring{width:132px;height:132px;position:relative;display:grid;place-items:center}
.timer-ring svg{width:132px;height:132px;transform:rotate(-90deg);overflow:visible}
.timer-track{stroke:var(--surface-blue);stroke-width:7;fill:none}
.timer-progress{stroke:var(--blue);stroke-width:7;stroke-linecap:round;fill:none;stroke-dasharray:314.16;stroke-dashoffset:314.16;transition:stroke-dashoffset .35s linear}
.timer-readout{position:absolute;font-size:27px;letter-spacing:-1.4px;font-weight:750;font-variant-numeric:tabular-nums}
.timer-status{font-size:11px;color:var(--muted);margin-top:3px;text-align:center}
.timer-modes{display:flex;gap:6px;margin-bottom:10px}
.timer-mode{border:1px solid var(--line);background:var(--surface-soft);color:var(--muted);padding:6px 9px;border-radius:8px;font-size:11px;font-weight:650}
.timer-mode[aria-pressed="true"]{background:var(--blue-soft);border-color:var(--line-strong);color:var(--blue-strong)}
.timer-actions{display:flex;gap:7px;margin-top:11px}
.timer-actions .btn{flex:1;padding:8px 10px}
.timer-note{font-size:10px;color:var(--muted);margin-top:9px}
.task-tools{display:grid;grid-template-columns:minmax(0,1fr) 145px;gap:8px;margin:12px 0 10px}
.task-tools .field{padding:8px 10px;font-size:12px}
.task{transition:background .18s ease,border-color .18s ease,transform .18s ease}
.task:hover{transform:translateY(-1px);background:var(--surface-soft)}
.card{animation:riseIn .48s both}
.grid .card:nth-child(2){animation-delay:.04s}.grid .card:nth-child(3){animation-delay:.08s}.grid .card:nth-child(4){animation-delay:.12s}.grid .card:nth-child(5){animation-delay:.16s}
.feature-row .card:first-child{animation-delay:.08s}.feature-row .card:last-child{animation-delay:.14s}
.btn{transition:background .16s,border-color .16s,transform .16s,box-shadow .16s}
.btn:hover{transform:translateY(-1px);box-shadow:0 5px 14px rgba(55,82,132,.1)}
@keyframes riseIn{from{opacity:0;transform:translateY(11px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:850px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.feature-row{grid-template-columns:1fr}}
@media(max-width:520px){.feature-row{gap:9px}.focus-layout{grid-template-columns:112px minmax(0,1fr);gap:10px}.timer-ring,.timer-ring svg{width:112px;height:112px}.timer-readout{font-size:23px}.task-tools{grid-template-columns:1fr 118px}.week-bars{gap:5px}.week-track{width:min(100%,28px)}.week-summary{gap:14px}}
@media(prefers-reduced-motion:reduce){.card,.grid .card,.feature-row .card{animation:none!important}.task,.btn,.week-fill,.timer-progress{transition:none!important}}
</style></head><body>
<div id="auth" class="authwrap"><div class="card authcard"><div class="authbrand"><div class="brand"><div class="logo" aria-label="JEE360 logo"><svg viewBox="0 0 40 40" fill="none" role="img" aria-hidden="true"><circle cx="20" cy="20" r="14.2" stroke="white" stroke-width="1.7" opacity=".72"/><path d="M20 4.8v4.1M35.2 20h-4.1M20 35.2v-4.1M4.8 20h4.1" stroke="white" stroke-width="1.8" stroke-linecap="round"/><path d="M13.2 25.9 18.1 14l3.1 8.1 5.6-7.2" stroke="white" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><circle cx="27.1" cy="14.7" r="2" fill="white"/></svg></div><div><h1>JEE360</h1><small>Preparation OS</small></div></div><button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch colour theme"><span class="theme-symbol">☾</span><span class="theme-label">Dark mode</span></button></div><div class="eyebrow">Your next chapter starts here</div><h2 id="authTitle">Welcome back.</h2><p id="authSub" class="muted">Sign in to continue your preparation.</p><form id="authForm"><div id="nameField" class="hidden"><label>Your name</label><input class="field" id="name" maxlength="60" autocomplete="name" placeholder="Your name"></div><label>Email address</label><input class="field" id="email" type="email" required autocomplete="email" placeholder="you@example.com"><label>Password</label><input class="field" id="password" type="password" minlength="10" required autocomplete="current-password" placeholder="At least 10 characters"><button class="btn" style="width:100%;margin-top:18px" id="authSubmit">Sign in</button></form><p class="notice" id="authError"></p><p class="notice">New here? <button class="btn ghost" id="toggleAuth" type="button">Create account</button></p><p class="notice">Your study data is private to your account.</p></div></div>
<div id="app" class="app hidden"><header class="top"><div class="brand"><div class="logo" aria-label="JEE360 logo"><svg viewBox="0 0 40 40" fill="none" role="img" aria-hidden="true"><circle cx="20" cy="20" r="14.2" stroke="white" stroke-width="1.7" opacity=".72"/><path d="M20 4.8v4.1M35.2 20h-4.1M20 35.2v-4.1M4.8 20h4.1" stroke="white" stroke-width="1.8" stroke-linecap="round"/><path d="M13.2 25.9 18.1 14l3.1 8.1 5.6-7.2" stroke="white" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><circle cx="27.1" cy="14.7" r="2" fill="white"/></svg></div><div><h1>JEE360</h1><small>Preparation OS</small></div></div><div class="topright"><span class="pill" id="today"></span><span class="pill" id="userName"></span><button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch colour theme"><span class="theme-symbol">☾</span><span class="theme-label">Dark mode</span></button><button class="btn ghost" id="logout">Sign out</button></div></header>
<div class="hero"><div><div class="eyebrow">Your preparation, in focus</div><h2 id="greeting">Make today count.</h2><p>Small consistent sessions. Measurable progress. One goal at a time.</p></div><button class="btn" id="addTaskTop">＋ Add task</button></div>
<div class="grid">
<div class="card"><div class="stat-label">Study time today</div><div class="stat" id="studyTime">0m</div><div class="stat-sub">Your effort, logged today</div><div class="progress"><span id="goalBar" style="width:0%"></span></div></div>
<div class="card"><div class="stat-label">Daily study goal</div><div class="stat" id="goalText">6h</div><div class="stat-sub">Your personal target</div></div>
<div class="card"><div class="stat-label">Tasks completed</div><div class="stat" id="doneCount">0</div><div class="stat-sub">All-time completed tasks</div></div>
<div class="card"><div class="stat-label">Tasks remaining</div><div class="stat" id="remainingCount">0</div><div class="stat-sub">Still on your list</div></div>
<div class="card"><div class="stat-label">Current streak</div><div class="stat" id="streakCount">0d</div><div class="stat-sub">Consecutive study days</div></div>
</div>
<div class="feature-row">
<section class="card insight-card">
<div class="section-head"><h3>Weekly study activity</h3><span class="muted" id="weekLabel" style="font-size:11px">Last 7 days</span></div>
<div id="weekBars" class="week-bars" aria-label="Study minutes for the last seven days"></div>
<div class="week-summary"><div><strong id="weekTotal">0m</strong><span>Total this week</span></div><div><strong id="weekAverage">0m</strong><span>Daily average</span></div><div><strong id="allTimeStudy">0h</strong><span>All-time study</span></div></div>
</section>
<section class="card timer-card">
<div class="section-head"><h3>Focus timer</h3><span class="muted" style="font-size:11px">Pomodoro</span></div>
<div class="focus-layout">
<div><div class="timer-ring"><svg viewBox="0 0 116 116" aria-hidden="true"><circle class="timer-track" cx="58" cy="58" r="50"></circle><circle id="timerProgress" class="timer-progress" cx="58" cy="58" r="50"></circle></svg><div class="timer-readout" id="timerReadout">25:00</div></div><div class="timer-status" id="timerStatus">Ready to focus</div></div>
<div>
<div class="timer-modes"><button type="button" class="timer-mode" data-mode="focus" aria-pressed="true">Focus 25m</button><button type="button" class="timer-mode" data-mode="break" aria-pressed="false">Break 5m</button></div>
<label for="focusSubject">Study subject</label><select class="field" id="focusSubject"><option value="">General study</option></select>
<div class="timer-actions"><button type="button" class="btn" id="timerStart">Start</button><button type="button" class="btn secondary" id="timerReset">Reset</button></div>
</div>
</div>
<div class="timer-note">Completed focus blocks are automatically added to your study log.</div>
</section>
</div>
<div class="layout"><section class="card"><div class="section-head"><h3>Today's focus</h3><button class="btn secondary" id="addTask">＋ New task</button></div><div class="task-tools"><input class="field" id="taskSearch" type="search" placeholder="Search your tasks…" aria-label="Search tasks"><select class="field" id="taskFilter" aria-label="Filter tasks"><option value="all">All tasks</option><option value="open">Open tasks</option><option value="done">Completed</option><option value="high">High priority</option></select></div><div id="tasks" class="task-list"><div class="empty">Loading your planner…</div></div></section><aside class="stack"><section class="card"><div class="section-head"><h3>Study subjects</h3><button class="btn ghost" id="addSubject">＋ Add</button></div><div id="subjects"></div></section><section class="card"><div class="section-head"><h3>Log a study session</h3></div><form id="studyForm"><label>What did you study?</label><input class="field" id="studyTitle" placeholder="e.g. Laws of Motion practice"><label>Subject</label><select class="field" id="studySubject"><option value="">General study</option></select><label>Duration (minutes)</label><input class="field" id="studyMinutes" type="number" min="1" max="1440" value="60" required><button class="btn" style="width:100%;margin-top:13px">Save study session</button></form></section><section class="card"><div class="section-head"><h3>Daily target</h3></div><label>Minutes per day</label><input class="field" id="dailyGoal" type="number" min="30" max="1440" value="360"><button class="btn secondary" style="width:100%;margin-top:10px" id="saveGoal">Update goal</button></section><section class="card"><div class="section-head"><h3>Account security</h3></div><form id="passwordForm"><label>Current password</label><input class="field" id="currentPassword" type="password" autocomplete="current-password" required><label>New password</label><input class="field" id="newPassword" type="password" minlength="10" maxlength="128" autocomplete="new-password" required><button class="btn secondary" style="width:100%;margin-top:12px">Change password</button></form><p class="notice">Changing your password signs out other active sessions.</p></section></aside></div><div class="foot">JEE360 · Built for focused preparation · Your data is saved securely to your account</div></div>
<div id="taskModal" class="modal hidden"><div class="modalbox"><div class="section-head"><h3>Create a task</h3><button class="btn ghost" id="closeTask">✕</button></div><form id="taskForm"><label>Task title</label><input class="field" id="taskTitle" maxlength="140" required placeholder="e.g. Complete friction PYQs"><label>Description (optional)</label><input class="field" id="taskDescription" maxlength="1000" placeholder="Add a short note"><label>Subject</label><select class="field" id="taskSubject"><option value="">No subject</option></select><div class="formrow"><div style="flex:1"><label>Priority</label><select class="field" id="taskPriority"><option value="medium">Medium</option><option value="high">High</option><option value="low">Low</option></select></div><div style="flex:1"><label>Estimated minutes</label><input class="field" id="taskMinutes" type="number" min="5" max="1440" value="45"></div></div><label>Due date</label><input class="field" id="taskDate" type="date"><button class="btn" style="width:100%;margin-top:18px">Create task</button></form></div></div>
<div id="subjectModal" class="modal hidden"><div class="modalbox"><div class="section-head"><h3>Add a subject</h3><button class="btn ghost" id="closeSubject">✕</button></div><form id="subjectForm"><label>Subject name</label><input class="field" id="subjectName" required maxlength="50" placeholder="Physics"><button class="btn" style="width:100%;margin-top:18px">Add subject</button></form></div></div><div id="toast" class="toast hidden"></div>
<script>
var state={user:null,tasks:[],subjects:[],settings:{daily_goal_minutes:360},weekly_minutes:[],streak_days:0,all_time_minutes:0};
var timer={mode:"focus",duration:1500,remaining:1500,running:false,deadline:0,handle:null};
function el(id){return document.getElementById(id)}
function applyTheme(theme){var selected=theme==="dark"?"dark":"light";document.documentElement.dataset.theme=selected;try{localStorage.setItem("jee360-theme",selected)}catch(e){}document.querySelectorAll("[data-theme-toggle]").forEach(function(btn){var dark=selected==="dark";var symbol=btn.querySelector(".theme-symbol");var label=btn.querySelector(".theme-label");if(symbol)symbol.textContent=dark?"☀":"☾";if(label)label.textContent=dark?"Light mode":"Dark mode";btn.setAttribute("aria-label",dark?"Switch to light mode":"Switch to dark mode");btn.setAttribute("aria-pressed",dark?"true":"false")})}
function initTheme(){var saved=null;try{saved=localStorage.getItem("jee360-theme")}catch(e){}var initial=saved||(window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light");applyTheme(initial);document.querySelectorAll("[data-theme-toggle]").forEach(function(btn){btn.addEventListener("click",function(){applyTheme(document.documentElement.dataset.theme==="dark"?"light":"dark")})})}
initTheme();

function showToast(message){el("toast").textContent=message;el("toast").classList.remove("hidden");setTimeout(function(){el("toast").classList.add("hidden")},2400)}
async function api(path,options){
  options=options||{};
  options.headers=Object.assign({"content-type":"application/json"},options.headers||{});
  options.credentials="same-origin";
  options.cache="no-store";
  var res;
  try{res=await fetch(path,options)}catch(networkError){throw new Error("Network connection failed. Check your internet and try again.")}
  var data=await res.json().catch(function(){return {}});
  if(!res.ok){
    if(res.status===429)throw new Error(data.error||"Too many attempts. Please wait a little and try again.");
    if(res.status===409)throw new Error(data.error||"This email already has an account. Switch to sign in.");
    throw new Error(data.error||("Request failed ("+res.status+"). Please try again."));
  }
  return data;
}
function escapeHtml(s){return String(s||"").replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function openModal(id){el(id).classList.remove("hidden")}
function closeModal(id){el(id).classList.add("hidden")}
function authMode(signup){
  el("authTitle").textContent=signup?"Create your account.":"Welcome back.";
  el("authSub").textContent=signup?"Create a private space for your study plan.":"Sign in to continue your preparation.";
  el("nameField").classList.toggle("hidden",!signup);
  el("name").required=signup;
  el("name").disabled=!signup;
  el("authSubmit").textContent=signup?"Create account":"Sign in";
  el("toggleAuth").textContent=signup?"I already have an account":"Create account";
  el("password").autocomplete=signup?"new-password":"current-password";
  el("auth").dataset.signup=signup?"1":"0";
  el("authError").textContent="";
  el("authError").classList.remove("error-text");
}
function renderTasks(){
  var search=(el("taskSearch").value||"").trim().toLowerCase();
  var filter=el("taskFilter").value||"all";
  var filtered=state.tasks.filter(function(t){
    var subject=state.subjects.find(function(item){return item.id===t.subject_id});
    var haystack=(t.title+" "+(t.description||"")+" "+(subject?subject.name:"")).toLowerCase();
    if(search&&haystack.indexOf(search)===-1)return false;
    if(filter==="open"&&t.status==="done")return false;
    if(filter==="done"&&t.status!=="done")return false;
    if(filter==="high"&&t.priority!=="high")return false;
    return true;
  });
  el("tasks").innerHTML=filtered.length?filtered.map(function(t){
    var subject=state.subjects.find(function(item){return item.id===t.subject_id});
    return '<div class="task '+(t.status==="done"?"done":"")+'"><button class="check" data-toggle="'+t.id+'" aria-label="Toggle task">'+(t.status==="done"?"✓":"")+'</button><div class="task-main"><div class="task-title">'+escapeHtml(t.title)+'</div><div class="task-meta">'+escapeHtml(subject?subject.name:"General")+' · '+(t.due_date?"Due "+escapeHtml(t.due_date):"No due date")+' · '+t.estimated_minutes+' min</div></div><span class="priority '+t.priority+'">'+t.priority+'</span><button class="btn ghost" data-delete="'+t.id+'" aria-label="Delete task">×</button></div>';
  }).join(""):'<div class="empty">'+(search||filter!=="all"?"No tasks match these filters.":"No tasks yet. Add one small goal and get started.")+'</div>';
}
function render(){
  var done=state.tasks.filter(function(t){return t.status==="done"}).length;
  var remaining=state.tasks.length-done;
  var mins=Number(state.today_minutes)||0;
  var goal=Number(state.settings.daily_goal_minutes)||360;
  el("studyTime").textContent=mins>=60?Math.floor(mins/60)+"h "+mins%60+"m":mins+"m";
  el("goalText").textContent=goal>=60?(goal/60).toFixed(goal%60?1:0)+"h":goal+"m";
  el("goalBar").style.width=Math.min(100,mins/goal*100)+"%";
  el("doneCount").textContent=state.completed||done;
  el("remainingCount").textContent=remaining;
  el("streakCount").textContent=(state.streak_days||0)+"d";
  el("dailyGoal").value=goal;
  el("userName").textContent=state.user.display_name;
  el("today").textContent=new Intl.DateTimeFormat("en-IN",{weekday:"short",day:"numeric",month:"short"}).format(new Date());
  var hour=new Date().getHours();
  el("greeting").textContent=hour<12?"Good morning.":hour<17?"Good afternoon.":"Good evening.";
  renderTasks();
  el("subjects").innerHTML=state.subjects.length?state.subjects.map(function(subject){return '<div class="subject"><span><i class="dot" style="background:'+escapeHtml(subject.color)+'"></i>'+escapeHtml(subject.name)+'</span><span class="muted">›</span></div>'}).join(""):'<p class="muted" style="font-size:13px">Add subjects to organise your study plan.</p>';
  var opts='<option value="">General study</option>'+state.subjects.map(function(subject){return '<option value="'+subject.id+'">'+escapeHtml(subject.name)+'</option>'}).join("");
  el("studySubject").innerHTML=opts;
  var previousFocusSubject=el("focusSubject").value;
  el("focusSubject").innerHTML=opts;
  if(state.subjects.some(function(subject){return subject.id===previousFocusSubject}))el("focusSubject").value=previousFocusSubject;
  el("taskSubject").innerHTML='<option value="">No subject</option>'+state.subjects.map(function(subject){return '<option value="'+subject.id+'">'+escapeHtml(subject.name)+'</option>'}).join("");
  var weekly=state.weekly_minutes||[];
  var maxMinutes=Math.max(60,...weekly.map(function(day){return Number(day.minutes)||0}));
  var total=weekly.reduce(function(sum,day){return sum+(Number(day.minutes)||0)},0);
  el("weekBars").innerHTML=weekly.map(function(day){
    var date=new Date(day.date+"T12:00:00");
    var label=new Intl.DateTimeFormat("en-IN",{weekday:"short"}).format(date);
    var minutes=Number(day.minutes)||0;
    var height=minutes?Math.max(5,minutes/maxMinutes*78):3;
    var value=minutes>=60?(minutes/60).toFixed(1)+"h":minutes+"m";
    return '<div class="week-col" title="'+day.date+": "+minutes+' minutes"><span class="week-value">'+(minutes?value:"")+'</span><div class="week-track"><i class="week-fill" style="height:'+height+'px"></i></div><span class="week-day">'+label+'</span></div>';
  }).join("");
  el("weekTotal").textContent=total>=60?(total/60).toFixed(1)+"h":total+"m";
  var average=Math.round(total/7);
  el("weekAverage").textContent=average>=60?(average/60).toFixed(1)+"h":average+"m";
  var allTime=Number(state.all_time_minutes)||0;
  el("allTimeStudy").textContent=allTime>=60?(allTime/60).toFixed(1)+"h":allTime+"m";
  updateTimerUI();
}
async function refresh(){var data=await api("/api/dashboard");state.tasks=data.tasks||[];state.subjects=data.subjects||[];state.today_minutes=data.today_minutes;state.completed=data.completed;state.settings=data.settings||state.settings;state.weekly_minutes=data.weekly_minutes||[];state.streak_days=data.streak_days||0;state.all_time_minutes=data.all_time_minutes||0;render()}
async function startApp(user){
  state.user=user;
  el("auth").classList.add("hidden");
  el("app").classList.remove("hidden");
  try{await refresh()}catch(error){
    showToast("Account is ready, but your dashboard could not load. Please refresh. "+error.message);
    console.error("JEE360 dashboard initial load failed",error);
  }
}
el("toggleAuth").onclick=function(){authMode(el("auth").dataset.signup!=="1")};
el("authForm").onsubmit=async function(e){
  e.preventDefault();
  var signup=el("auth").dataset.signup==="1";
  var submit=el("authSubmit");
  el("authError").textContent="";
  submit.disabled=true;
  submit.textContent=signup?"Creating account…":"Signing in…";
  try{
    var data=await api(signup?"/api/auth/register":"/api/auth/login",{method:"POST",body:JSON.stringify({name:el("name").value.trim(),email:el("email").value.trim(),password:el("password").value})});
    if(!data.user)throw new Error("The server did not confirm your account. Please try again.");
    await startApp(data.user);
  }catch(err){
    el("authError").textContent=err.message;
    el("authError").classList.add("error-text");
    submit.textContent=signup?"Create account":"Sign in";
  }finally{
    submit.disabled=false;
    if(el("auth").dataset.signup==="1")submit.textContent="Create account";
    else submit.textContent="Sign in";
  }
};
el("logout").onclick=async function(){await api("/api/auth/logout",{method:"POST",body:"{}"});state.user=null;el("app").classList.add("hidden");el("auth").classList.remove("hidden");el("password").value="";authMode(false)};
el("addTask").onclick=el("addTaskTop").onclick=function(){openModal("taskModal")};el("closeTask").onclick=function(){closeModal("taskModal")};el("addSubject").onclick=function(){openModal("subjectModal")};el("closeSubject").onclick=function(){closeModal("subjectModal")};
el("taskForm").onsubmit=async function(e){e.preventDefault();try{await api("/api/tasks",{method:"POST",body:JSON.stringify({title:el("taskTitle").value,description:el("taskDescription").value,subject_id:el("taskSubject").value,priority:el("taskPriority").value,estimated_minutes:el("taskMinutes").value,due_date:el("taskDate").value||null})});el("taskForm").reset();closeModal("taskModal");await refresh();showToast("Task added to your planner.")}catch(err){showToast(err.message)}};
el("subjectForm").onsubmit=async function(e){e.preventDefault();try{await api("/api/subjects",{method:"POST",body:JSON.stringify({name:el("subjectName").value})});el("subjectForm").reset();closeModal("subjectModal");await refresh();showToast("Subject added.")}catch(err){showToast(err.message)}};
el("tasks").onclick=async function(e){var toggle=e.target.closest("[data-toggle]");var del=e.target.closest("[data-delete]");try{if(toggle){var task=state.tasks.find(function(t){return t.id===toggle.dataset.toggle});await api("/api/tasks/"+task.id,{method:"PATCH",body:JSON.stringify({status:task.status==="done"?"todo":"done"})});await refresh()}if(del){await api("/api/tasks/"+del.dataset.delete,{method:"DELETE"});await refresh();showToast("Task deleted.")}}catch(err){showToast(err.message)}};
el("studyForm").onsubmit=async function(e){e.preventDefault();try{await api("/api/study-sessions",{method:"POST",body:JSON.stringify({title:el("studyTitle").value||"Study session",subject_id:el("studySubject").value,duration_minutes:el("studyMinutes").value})});el("studyTitle").value="";await refresh();showToast("Study session saved. Keep it up!") }catch(err){showToast(err.message)}};
el("saveGoal").onclick=async function(){try{await api("/api/settings",{method:"PATCH",body:JSON.stringify({daily_goal_minutes:el("dailyGoal").value})});await refresh();showToast("Daily target updated.")}catch(err){showToast(err.message)}};
el("passwordForm").onsubmit=async function(e){e.preventDefault();try{await api("/api/auth/password",{method:"POST",body:JSON.stringify({current_password:el("currentPassword").value,new_password:el("newPassword").value})});el("passwordForm").reset();showToast("Password changed. Other sessions were signed out.")}catch(err){showToast(err.message)}};
function formatTimer(seconds){var safe=Math.max(0,seconds);return String(Math.floor(safe/60)).padStart(2,"0")+":"+String(safe%60).padStart(2,"0")}
function updateTimerUI(){
  var progress=timer.duration?1-timer.remaining/timer.duration:0;
  el("timerReadout").textContent=formatTimer(timer.remaining);
  el("timerProgress").style.strokeDashoffset=String(314.16*(1-progress));
  el("timerStart").textContent=timer.running?"Pause":timer.remaining===0?"Start again":"Start";
  el("timerStatus").textContent=timer.running?"Stay with this session":timer.mode==="break"?"Take a breather":timer.remaining===0?"Block complete":"Ready to focus";
  document.querySelectorAll("[data-mode]").forEach(function(button){button.setAttribute("aria-pressed",button.dataset.mode===timer.mode?"true":"false")});
  document.title=(timer.running?formatTimer(timer.remaining)+" · ":"")+"JEE360 — Your preparation, in focus";
}
function stopTimerInterval(){if(timer.handle){clearInterval(timer.handle);timer.handle=null}}
function pauseTimer(){if(timer.running){timer.remaining=Math.max(0,Math.ceil((timer.deadline-Date.now())/1000));timer.running=false;stopTimerInterval();updateTimerUI()}}
function setTimerMode(mode){
  pauseTimer();
  timer.mode=mode==="break"?"break":"focus";
  timer.duration=timer.mode==="focus"?1500:300;
  timer.remaining=timer.duration;
  timer.deadline=0;
  updateTimerUI();
}
async function finishTimer(){
  timer.running=false;timer.remaining=0;stopTimerInterval();updateTimerUI();
  if(timer.mode==="focus"){
    try{
      await api("/api/study-sessions",{method:"POST",body:JSON.stringify({title:"Focus session · 25 minutes",subject_id:el("focusSubject").value||null,duration_minutes:25})});
      await refresh();
      showToast("Focus block saved to your study log. Great work!");
    }catch(error){showToast("Timer finished, but saving failed: "+error.message)}
  }else{showToast("Break complete. Ready for another focus block?")}
  updateTimerUI();
}
function tickTimer(){
  if(!timer.running)return;
  timer.remaining=Math.max(0,Math.ceil((timer.deadline-Date.now())/1000));
  if(timer.remaining===0){finishTimer();return}
  updateTimerUI();
}
el("timerStart").onclick=function(){
  if(timer.running){pauseTimer();return}
  if(timer.remaining<=0)timer.remaining=timer.duration;
  timer.running=true;timer.deadline=Date.now()+timer.remaining*1000;
  stopTimerInterval();timer.handle=setInterval(tickTimer,250);updateTimerUI();
};
el("timerReset").onclick=function(){pauseTimer();timer.remaining=timer.duration;timer.deadline=0;updateTimerUI()};
document.querySelectorAll("[data-mode]").forEach(function(button){button.addEventListener("click",function(){setTimerMode(button.dataset.mode)})});
document.addEventListener("visibilitychange",function(){if(!document.hidden)tickTimer()});
el("taskSearch").addEventListener("input",renderTasks);
el("taskFilter").addEventListener("change",renderTasks);
updateTimerUI();
api("/api/auth/me").then(function(data){if(data.user)startApp(data.user)}).catch(function(){});
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.indexOf("/api/") === 0) {
      try { return await handleApi(request, env, url.pathname); }
      catch (error) { console.error("JEE360 request failed", error); return json({ error: "A server error occurred. Please try again." }, 500); }
    }
    if (request.method !== "GET" && request.method !== "HEAD") return new Response("Method not allowed", { status: 405 });
    return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", "content-security-policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'" } });
  }
};
