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
async function body(request) {
  try { return await request.json(); } catch (_) { return null; }
}
function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  const url = new URL(request.url);
  return origin === url.origin;
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
  await env.DB.prepare("INSERT INTO auth_rate_limits (key,hits,window_start) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET hits=CASE WHEN window_start<=? THEN 1 ELSE hits+1 END,window_start=CASE WHEN window_start<=? THEN excluded.window_start ELSE window_start END").bind(key, now, cutoff, cutoff).run();
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
    const row = await env.DB.prepare("SELECT COUNT(*) AS tables_ready FROM sqlite_master WHERE type='table' AND name IN ('users','sessions','tasks','subjects','study_sessions','user_settings')").first();
    return json({ ok: true, service: "JEE360", database: Number(row.tables_ready) === 6 ? "connected" : "schema-incomplete" });
  }
  if (path === "/api/auth/register" && method === "POST") {
    const data = await body(request);
    if (!data || typeof data.email !== "string" || typeof data.password !== "string" || typeof data.name !== "string") return json({ error: "Please provide your name, email and password." }, 400);
    const email = data.email.trim().toLowerCase();
    const name = data.name.trim().slice(0, 60);
    if (!name || !validEmail(email)) return json({ error: "Enter a valid name and email address." }, 400);
    if (data.password.length < 10 || data.password.length > 128) return json({ error: "Use a password between 10 and 128 characters." }, 400);
    if (await rateLimited(request, env, "register", 5, 3600)) return json({ error: "Too many sign-up attempts. Please try again later." }, 429);
    const id = crypto.randomUUID();
    const salt = randomHex(16);
    const hash = await passwordHash(data.password, salt, ITERATIONS);
    try {
      await env.DB.prepare("INSERT INTO users (id,email,display_name,password_salt,password_hash,password_iterations) VALUES (?,?,?,?,?,?)").bind(id, email, name, salt, hash, ITERATIONS).run();
    } catch (_) { return json({ error: "An account with this email may already exist." }, 409); }
    await env.DB.prepare("INSERT INTO user_settings (user_id) VALUES (?)").bind(id).run();
    const token = await createSession(id, env);
    return json({ user: { id: id, email: email, display_name: name } }, 201, { "set-cookie": cookie(token, SESSION_DAYS * 86400) });
  }
  if (path === "/api/auth/login" && method === "POST") {
    const data = await body(request);
    if (!data || typeof data.email !== "string" || typeof data.password !== "string") return json({ error: "Enter your email and password." }, 400);
    const email = data.email.trim().toLowerCase();
    if (await rateLimited(request, env, "login", 10, 900)) return json({ error: "Too many sign-in attempts. Please wait 15 minutes." }, 429);
    const row = await env.DB.prepare("SELECT id,email,display_name,password_salt,password_hash,password_iterations FROM users WHERE email=?").bind(email).first();
    const salt = row ? row.password_salt : "jee360-invalid-user-salt";
    const expected = row ? row.password_hash : "not-a-valid-password-hash";
    const actual = await passwordHash(data.password.slice(0, 128), salt, row ? Number(row.password_iterations) : ITERATIONS);
    if (!row || actual !== expected) return json({ error: "Email or password is incorrect." }, 401);
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

  if (path === "/api/dashboard" && method === "GET") {
    const results = await Promise.all([
      env.DB.prepare("SELECT id,title,description,due_date,priority,status,estimated_minutes,subject_id,created_at FROM tasks WHERE user_id=? ORDER BY CASE status WHEN 'in_progress' THEN 0 WHEN 'todo' THEN 1 ELSE 2 END, due_date IS NULL, due_date LIMIT 100").bind(userId).all(),
      env.DB.prepare("SELECT id,name,color FROM subjects WHERE user_id=? ORDER BY name").bind(userId).all(),
      env.DB.prepare("SELECT COALESCE(SUM(duration_minutes),0) AS total FROM study_sessions WHERE user_id=? AND studied_on=date('now','localtime')").bind(userId).first(),
      env.DB.prepare("SELECT COUNT(*) AS completed FROM tasks WHERE user_id=? AND status='done'").bind(userId).first(),
      env.DB.prepare("SELECT target_exam,daily_goal_minutes,timezone FROM user_settings WHERE user_id=?").bind(userId).first()
    ]);
    return json({ tasks: results[0].results, subjects: results[1].results, today_minutes: results[2].total, completed: results[3].completed, settings: results[4] || { target_exam: "JEE Main + Advanced", daily_goal_minutes: 360, timezone: "Asia/Kolkata" } });
  }
  if (path === "/api/tasks" && method === "POST") {
    const data = await body(request);
    if (!data || typeof data.title !== "string" || !data.title.trim()) return json({ error: "Task title is required." }, 400);
    const priority = ["low","medium","high"].includes(data.priority) ? data.priority : "medium";
    const status = ["todo","in_progress","done"].includes(data.status) ? data.status : "todo";
    const mins = Math.max(5, Math.min(1440, Number(data.estimated_minutes) || 30));
    const id = crypto.randomUUID();
    const subjectId = typeof data.subject_id === "string" && data.subject_id ? data.subject_id : null;
    if (subjectId) {
      const s = await env.DB.prepare("SELECT id FROM subjects WHERE id=? AND user_id=?").bind(subjectId,userId).first();
      if (!s) return json({ error: "Subject not found." }, 404);
    }
    await env.DB.prepare("INSERT INTO tasks (id,user_id,subject_id,title,description,due_date,priority,status,estimated_minutes) VALUES (?,?,?,?,?,?,?,?,?)").bind(id,userId,subjectId,data.title.trim().slice(0,140),String(data.description || "").slice(0,1000),data.due_date || null,priority,status,mins).run();
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
    } catch (_) { return json({ error: "That subject already exists." }, 409); }
    return json({ id: id }, 201);
  }
  if (path === "/api/study-sessions" && method === "POST") {
    const data = await body(request);
    const minutes = Math.max(1,Math.min(1440,Number(data && data.duration_minutes) || 0));
    if (!minutes) return json({ error: "Enter a valid study duration." }, 400);
    const subjectId = data.subject_id || null;
    if (subjectId) {
      const s = await env.DB.prepare("SELECT id FROM subjects WHERE id=? AND user_id=?").bind(subjectId,userId).first();
      if (!s) return json({ error: "Subject not found." }, 404);
    }
    await env.DB.prepare("INSERT INTO study_sessions (id,user_id,subject_id,title,duration_minutes,studied_on,notes) VALUES (?,?,?,?,?,date('now','localtime'),?)").bind(crypto.randomUUID(),userId,subjectId,String(data.title || "Study session").slice(0,120),minutes,String(data.notes || "").slice(0,500)).run();
    return json({ ok: true }, 201);
  }
  if (path === "/api/settings" && method === "PATCH") {
    const data = await body(request);
    const goal = Math.max(30,Math.min(1440,Number(data.daily_goal_minutes) || 360));
    await env.DB.prepare("INSERT INTO user_settings (user_id,target_exam,daily_goal_minutes,timezone,updated_at) VALUES (?,?,?,?,datetime('now')) ON CONFLICT(user_id) DO UPDATE SET target_exam=excluded.target_exam,daily_goal_minutes=excluded.daily_goal_minutes,timezone=excluded.timezone,updated_at=datetime('now')").bind(userId,String(data.target_exam || "JEE Main + Advanced").slice(0,80),goal,String(data.timezone || "Asia/Kolkata").slice(0,60)).run();
    return json({ ok: true });
  }
  return json({ error: "Not found." }, 404);
}

const PAGE = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#090d18"><title>JEE360 — Your preparation, in focus</title>
<style>
:root{color-scheme:dark;--bg:#090d18;--panel:#111a2b;--panel2:#162238;--line:#26344c;--muted:#8b9bb5;--text:#f3f6fc;--blue:#8295ff;--cyan:#62d5d0;--good:#55d6a2;--warn:#f6c56f;--red:#ff8294}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 20% -10%,#202c55 0,transparent 42%),var(--bg);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;min-height:100vh}button,input,select,textarea{font:inherit}button{cursor:pointer}.hidden{display:none!important}.muted{color:var(--muted)}.app{max-width:1240px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:26px}.brand{display:flex;align-items:center;gap:12px}.logo{width:42px;height:42px;border-radius:14px;background:linear-gradient(135deg,#8c9cff,#5edbd0);display:grid;place-items:center;color:#08111c;font-weight:900;font-size:19px;box-shadow:0 8px 30px #6b8cff33}.brand h1{font-size:19px;margin:0;letter-spacing:.2px}.brand small{display:block;color:var(--muted);font-size:11px;letter-spacing:1.8px;text-transform:uppercase}.topright{display:flex;align-items:center;gap:12px}.pill{border:1px solid var(--line);background:#10192a;padding:8px 12px;border-radius:99px;color:var(--muted);font-size:12px}.btn{border:0;border-radius:12px;padding:10px 15px;background:linear-gradient(135deg,#8798ff,#6cdbd0);color:#09121f;font-weight:750}.btn.secondary{background:#1b2940;color:#dce5f6;border:1px solid var(--line)}.btn.ghost{background:transparent;color:var(--muted);border:1px solid var(--line)}.btn.danger{background:#402331;color:#ffb5c0;border:1px solid #75404d}.hero{display:flex;justify-content:space-between;align-items:end;gap:16px;margin:30px 0 20px}.eyebrow{color:var(--cyan);font-size:11px;font-weight:800;letter-spacing:2px;text-transform:uppercase}.hero h2{font-size:clamp(25px,4vw,36px);letter-spacing:-1.3px;line-height:1.15;margin:7px 0}.hero p{margin:0;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:linear-gradient(145deg,#141f33ee,#0f1727ee);border:1px solid var(--line);border-radius:20px;padding:18px;box-shadow:0 14px 40px #0002}.stat-label{font-size:12px;color:var(--muted)}.stat{font-size:29px;font-weight:800;letter-spacing:-1px;margin:8px 0 2px}.stat-sub{font-size:11px;color:var(--muted)}.layout{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(270px,.8fr);gap:16px;margin-top:16px}.section-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:15px}.section-head h3{margin:0;font-size:16px}.task-list{display:grid;gap:9px}.task{display:flex;align-items:center;gap:12px;padding:13px;border:1px solid #25334a;border-radius:14px;background:#0d1626}.check{width:21px;height:21px;border:1px solid #53637c;border-radius:7px;background:transparent;flex:none;color:#08121c}.task-main{min-width:0;flex:1}.task-title{font-weight:650;overflow-wrap:anywhere}.task.done .task-title{text-decoration:line-through;color:#8190a7}.task-meta{font-size:11px;color:var(--muted);margin-top:3px}.priority{font-size:10px;border-radius:99px;padding:4px 8px;background:#26334a;color:#c5d0e4}.priority.high{background:#472d38;color:#ffadba}.priority.low{background:#193b3a;color:#83e0cb}.progress{height:8px;background:#26334b;border-radius:99px;overflow:hidden;margin:12px 0}.progress span{display:block;height:100%;background:linear-gradient(90deg,#8798ff,#62d5d0);border-radius:99px}.formrow{display:flex;gap:8px}.field{width:100%;border:1px solid #2a3952;background:#0a1322;color:var(--text);border-radius:11px;padding:11px 12px;outline:none}.field:focus{border-color:#8295ff;box-shadow:0 0 0 3px #8295ff20}.field::placeholder{color:#65758e}label{display:block;font-size:12px;color:var(--muted);margin:12px 0 6px}.stack{display:grid;gap:8px}.subject{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid #243149;font-size:13px}.dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:9px}.modal{position:fixed;inset:0;background:#050914c9;display:grid;place-items:center;padding:16px;z-index:5}.modalbox{width:min(440px,100%);background:#111b2d;border:1px solid #33435e;border-radius:22px;padding:24px;box-shadow:0 24px 90px #0009}.modalbox h2{margin:0 0 4px}.authwrap{min-height:100vh;display:grid;place-items:center;padding:20px}.authcard{width:min(430px,100%);padding:28px}.authcard h2{font-size:27px;letter-spacing:-.8px;margin:0 0 4px}.notice{font-size:12px;color:var(--muted);margin-top:15px}.empty{padding:25px;text-align:center;color:var(--muted);border:1px dashed #34445e;border-radius:14px}.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);padding:11px 16px;border-radius:12px;background:#e5f7f4;color:#10232a;font-weight:700;z-index:10;box-shadow:0 10px 30px #0005}.foot{padding:22px 0;color:#667792;text-align:center;font-size:11px}
@media(max-width:850px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.layout{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}.app{padding:17px}}@media(max-width:480px){.top{align-items:flex-start}.topright{gap:6px}.topright .pill{display:none}.grid{gap:9px}.card{padding:14px;border-radius:16px}.stat{font-size:24px}.formrow{flex-wrap:wrap}.hero h2{font-size:28px}}
</style></head><body>
<div id="auth" class="authwrap"><div class="card authcard"><div class="brand" style="margin-bottom:26px"><div class="logo">360</div><div><h1>JEE360</h1><small>Preparation OS</small></div></div><div class="eyebrow">Your next chapter starts here</div><h2 id="authTitle">Welcome back.</h2><p id="authSub" class="muted">Sign in to continue your preparation.</p><form id="authForm"><div id="nameField" class="hidden"><label>Your name</label><input class="field" id="name" maxlength="60" autocomplete="name" placeholder="Your name"></div><label>Email address</label><input class="field" id="email" type="email" required autocomplete="email" placeholder="you@example.com"><label>Password</label><input class="field" id="password" type="password" minlength="10" required autocomplete="current-password" placeholder="At least 10 characters"><button class="btn" style="width:100%;margin-top:18px" id="authSubmit">Sign in</button></form><p class="notice" id="authError"></p><p class="notice">New here? <button class="btn ghost" id="toggleAuth" type="button">Create account</button></p><p class="notice">Your study data is private to your account.</p></div></div>
<div id="app" class="app hidden"><header class="top"><div class="brand"><div class="logo">360</div><div><h1>JEE360</h1><small>Preparation OS</small></div></div><div class="topright"><span class="pill" id="today"></span><span class="pill" id="userName"></span><button class="btn ghost" id="logout">Sign out</button></div></header>
<div class="hero"><div><div class="eyebrow">Your preparation, in focus</div><h2 id="greeting">Make today count.</h2><p>Small consistent sessions. Measurable progress. One goal at a time.</p></div><button class="btn" id="addTaskTop">＋ Add task</button></div>
<div class="grid"><div class="card"><div class="stat-label">Study time today</div><div class="stat" id="studyTime">0m</div><div class="stat-sub">Your daily learning streak starts here</div><div class="progress"><span id="goalBar" style="width:0%"></span></div></div><div class="card"><div class="stat-label">Daily study goal</div><div class="stat" id="goalText">6h</div><div class="stat-sub">Personal target</div></div><div class="card"><div class="stat-label">Tasks completed</div><div class="stat" id="doneCount">0</div><div class="stat-sub">All-time completed tasks</div></div><div class="card"><div class="stat-label">Tasks remaining</div><div class="stat" id="remainingCount">0</div><div class="stat-sub">Keep moving forward</div></div></div>
<div class="layout"><section class="card"><div class="section-head"><h3>Today's focus</h3><button class="btn secondary" id="addTask">＋ New task</button></div><div id="tasks" class="task-list"><div class="empty">Loading your planner…</div></div></section><aside class="stack"><section class="card"><div class="section-head"><h3>Study subjects</h3><button class="btn ghost" id="addSubject">＋ Add</button></div><div id="subjects"></div></section><section class="card"><div class="section-head"><h3>Log a study session</h3></div><form id="studyForm"><label>What did you study?</label><input class="field" id="studyTitle" placeholder="e.g. Laws of Motion practice"><label>Subject</label><select class="field" id="studySubject"><option value="">General study</option></select><label>Duration (minutes)</label><input class="field" id="studyMinutes" type="number" min="1" max="1440" value="60" required><button class="btn" style="width:100%;margin-top:13px">Save study session</button></form></section><section class="card"><div class="section-head"><h3>Daily target</h3></div><label>Minutes per day</label><input class="field" id="dailyGoal" type="number" min="30" max="1440" value="360"><button class="btn secondary" style="width:100%;margin-top:10px" id="saveGoal">Update goal</button></section></aside></div><div class="foot">JEE360 · Built for focused preparation · Your data is saved securely to your account</div></div>
<div id="taskModal" class="modal hidden"><div class="modalbox"><div class="section-head"><h3>Create a task</h3><button class="btn ghost" id="closeTask">✕</button></div><form id="taskForm"><label>Task title</label><input class="field" id="taskTitle" maxlength="140" required placeholder="e.g. Complete friction PYQs"><label>Description (optional)</label><input class="field" id="taskDescription" maxlength="1000" placeholder="Add a short note"><label>Subject</label><select class="field" id="taskSubject"><option value="">No subject</option></select><div class="formrow"><div style="flex:1"><label>Priority</label><select class="field" id="taskPriority"><option value="medium">Medium</option><option value="high">High</option><option value="low">Low</option></select></div><div style="flex:1"><label>Estimated minutes</label><input class="field" id="taskMinutes" type="number" min="5" max="1440" value="45"></div></div><label>Due date</label><input class="field" id="taskDate" type="date"><button class="btn" style="width:100%;margin-top:18px">Create task</button></form></div></div>
<div id="subjectModal" class="modal hidden"><div class="modalbox"><div class="section-head"><h3>Add a subject</h3><button class="btn ghost" id="closeSubject">✕</button></div><form id="subjectForm"><label>Subject name</label><input class="field" id="subjectName" required maxlength="50" placeholder="Physics"><button class="btn" style="width:100%;margin-top:18px">Add subject</button></form></div></div><div id="toast" class="toast hidden"></div>
<script>
var state={user:null,tasks:[],subjects:[],settings:{daily_goal_minutes:360}};
function el(id){return document.getElementById(id)}
function showToast(message){el("toast").textContent=message;el("toast").classList.remove("hidden");setTimeout(function(){el("toast").classList.add("hidden")},2400)}
async function api(path,options){options=options||{};options.headers=Object.assign({"content-type":"application/json"},options.headers||{});var res=await fetch(path,options);var data=await res.json().catch(function(){return {}});if(!res.ok)throw new Error(data.error||"Something went wrong.");return data}
function escapeHtml(s){return String(s||"").replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function openModal(id){el(id).classList.remove("hidden")}
function closeModal(id){el(id).classList.add("hidden")}
function authMode(signup){el("authTitle").textContent=signup?"Create your account.":"Welcome back.";el("authSub").textContent=signup?"Your personal study space is one step away.":"Sign in to continue your preparation.";el("nameField").classList.toggle("hidden",!signup);el("authSubmit").textContent=signup?"Create account":"Sign in";el("toggleAuth").textContent=signup?"I already have an account":"Create account";el("password").autocomplete=signup?"new-password":"current-password";el("auth").dataset.signup=signup?"1":"0";el("authError").textContent=""}
function render(){var done=state.tasks.filter(function(t){return t.status==="done"}).length;var remaining=state.tasks.length-done;var mins=Number(state.today_minutes)||0;var goal=Number(state.settings.daily_goal_minutes)||360;el("studyTime").textContent=mins>=60?Math.floor(mins/60)+"h "+mins%60+"m":mins+"m";el("goalText").textContent=goal>=60?(goal/60).toFixed(goal%60?1:0)+"h":goal+"m";el("goalBar").style.width=Math.min(100,mins/goal*100)+"%";el("doneCount").textContent=state.completed||done;el("remainingCount").textContent=remaining;el("dailyGoal").value=goal;el("userName").textContent=state.user.display_name;el("today").textContent=new Intl.DateTimeFormat("en-IN",{weekday:"short",day:"numeric",month:"short"}).format(new Date());var hour=new Date().getHours();el("greeting").textContent=hour<12?"Good morning.":hour<17?"Good afternoon.":"Good evening.";el("tasks").innerHTML=state.tasks.length?state.tasks.map(function(t){var subject=state.subjects.find(function(s){return s.id===t.subject_id});return '<div class="task '+(t.status==="done"?"done":"")+'"><button class="check" data-toggle="'+t.id+'" aria-label="Toggle task">'+(t.status==="done"?"✓":"")+'</button><div class="task-main"><div class="task-title">'+escapeHtml(t.title)+'</div><div class="task-meta">'+escapeHtml(subject?subject.name:"General")+' · '+(t.due_date?"Due "+escapeHtml(t.due_date):"No due date")+' · '+t.estimated_minutes+' min</div></div><span class="priority '+t.priority+'">'+t.priority+'</span><button class="btn ghost" data-delete="'+t.id+'" aria-label="Delete task">×</button></div>'}).join(""):'<div class="empty">No tasks yet. Add one small goal and get started.</div>';el("subjects").innerHTML=state.subjects.length?state.subjects.map(function(s){return '<div class="subject"><span><i class="dot" style="background:'+escapeHtml(s.color)+'"></i>'+escapeHtml(s.name)+'</span><span class="muted">›</span></div>'}).join(""):'<p class="muted" style="font-size:13px">Add subjects to organise your study plan.</p>';var opts='<option value="">General study</option>'+state.subjects.map(function(s){return '<option value="'+s.id+'">'+escapeHtml(s.name)+'</option>'}).join("");el("studySubject").innerHTML=opts;el("taskSubject").innerHTML='<option value="">No subject</option>'+state.subjects.map(function(s){return '<option value="'+s.id+'">'+escapeHtml(s.name)+'</option>'}).join("")}
async function refresh(){var data=await api("/api/dashboard");state.tasks=data.tasks||[];state.subjects=data.subjects||[];state.today_minutes=data.today_minutes;state.completed=data.completed;state.settings=data.settings||state.settings;render()}
async function startApp(user){state.user=user;el("auth").classList.add("hidden");el("app").classList.remove("hidden");await refresh()}
el("toggleAuth").onclick=function(){authMode(el("auth").dataset.signup!=="1")};
el("authForm").onsubmit=async function(e){e.preventDefault();var signup=el("auth").dataset.signup==="1";el("authError").textContent="";try{var data=await api(signup?"/api/auth/register":"/api/auth/login",{method:"POST",body:JSON.stringify({name:el("name").value,email:el("email").value,password:el("password").value})});await startApp(data.user)}catch(err){el("authError").textContent=err.message}};
el("logout").onclick=async function(){await api("/api/auth/logout",{method:"POST",body:"{}"});state.user=null;el("app").classList.add("hidden");el("auth").classList.remove("hidden");el("password").value="";authMode(false)};
el("addTask").onclick=el("addTaskTop").onclick=function(){openModal("taskModal")};el("closeTask").onclick=function(){closeModal("taskModal")};el("addSubject").onclick=function(){openModal("subjectModal")};el("closeSubject").onclick=function(){closeModal("subjectModal")};
el("taskForm").onsubmit=async function(e){e.preventDefault();try{await api("/api/tasks",{method:"POST",body:JSON.stringify({title:el("taskTitle").value,description:el("taskDescription").value,subject_id:el("taskSubject").value,priority:el("taskPriority").value,estimated_minutes:el("taskMinutes").value,due_date:el("taskDate").value||null})});el("taskForm").reset();closeModal("taskModal");await refresh();showToast("Task added to your planner.")}catch(err){showToast(err.message)}};
el("subjectForm").onsubmit=async function(e){e.preventDefault();try{await api("/api/subjects",{method:"POST",body:JSON.stringify({name:el("subjectName").value})});el("subjectForm").reset();closeModal("subjectModal");await refresh();showToast("Subject added.")}catch(err){showToast(err.message)}};
el("tasks").onclick=async function(e){var toggle=e.target.closest("[data-toggle]");var del=e.target.closest("[data-delete]");try{if(toggle){var task=state.tasks.find(function(t){return t.id===toggle.dataset.toggle});await api("/api/tasks/"+task.id,{method:"PATCH",body:JSON.stringify({status:task.status==="done"?"todo":"done"})});await refresh()}if(del){await api("/api/tasks/"+del.dataset.delete,{method:"DELETE"});await refresh();showToast("Task deleted.")}}catch(err){showToast(err.message)}};
el("studyForm").onsubmit=async function(e){e.preventDefault();try{await api("/api/study-sessions",{method:"POST",body:JSON.stringify({title:el("studyTitle").value||"Study session",subject_id:el("studySubject").value,duration_minutes:el("studyMinutes").value})});el("studyTitle").value="";await refresh();showToast("Study session saved. Keep it up!") }catch(err){showToast(err.message)}};
el("saveGoal").onclick=async function(){try{await api("/api/settings",{method:"PATCH",body:JSON.stringify({daily_goal_minutes:el("dailyGoal").value})});await refresh();showToast("Daily target updated.")}catch(err){showToast(err.message)}};
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
