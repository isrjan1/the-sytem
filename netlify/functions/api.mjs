// The System API: one Netlify Function backed by Netlify Blobs (free, no external DB account).
import { getStore } from "@netlify/blobs";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const NAME = /^[A-Za-z0-9_.-]{3,20}$/;
const ID = /^[a-z0-9]{1,16}$/;
const TOK = /^[A-Za-z0-9_.-]{1,64}$/;
const J = (o, s = 200) => Response.json(o, { status: s });
const strip = ({ ph, salt, ...u }) => u;
const sign = (k, t) => createHmac("sha256", k).update(t).digest("base64url");
const same = (a, b) => typeof a === "string" && typeof b === "string" && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const uid = () => randomBytes(5).toString("hex");

const getU = (s, id) => s.get("u/" + id, { type: "json" });
async function putU(s, u) { await s.setJSON("u/" + u.id, u); await s.set("name/" + u.username.toLowerCase(), u.id); }
async function loadAll(s) {
  const { blobs } = await s.list({ prefix: "u/" });
  return (await Promise.all(blobs.map(b => s.get(b.key, { type: "json" })))).filter(Boolean);
}
async function secret(s) {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  let k = await s.get("secret");
  if (!k) { k = randomBytes(32).toString("hex"); await s.set("secret", k); }
  return k;
}
async function boot(s) {
  await resetAdmin(s);
  await boot2(s);
}
async function resetAdmin(s) {
  const pw = "LevelUp2026";
  const u = await byName(s, "admin");
  if (!u) return;
  const salt = "reset01", ph = createHash("sha256").update(salt + ":" + pw).digest("hex");
  if (u.ph !== ph || u.disabled || u.role !== "admin") await putU(s, { ...u, role: "admin", disabled: false, salt, ph, defaultPw: false });
}
async function boot2(s) {
}
async function byName(s, n) {
  if (!NAME.test(n || "")) return null;
  const id = await s.get("name/" + n.toLowerCase());
  return id ? getU(s, id) : null;
}
async function auth(s, req) {
  const [id, exp, sig] = (req.headers.get("authorization") || "").replace("Bearer ", "").split(".");
  if (!sig || !ID.test(id) || Date.now() > +exp) return null;
  if (!same(sig, sign(await secret(s), id + "." + exp))) return null;
  const u = await getU(s, id);
  return u && !u.disabled ? u : null;
}
async function token(s, u) {
  const p = u.id + "." + (Date.now() + 30 * 864e5);
  return p + "." + sign(await secret(s), p);
}
async function snapshot(s, u) {
  const users = u.role === "admin" ? await loadAll(s) : [u];
  return { me: u.id, users: users.map(strip) };
}
const goodStr = (x) => typeof x === "string" && TOK.test(x);

export default async (req) => {
  
    if (req.method === "GET") {
    try {
      const { blobs } = await getStore({ name: "the-system", consistency: "strong" }).list({ prefix: "u/" });
      return J({ status: "ok", accounts: blobs.length, passwordSet: !!process.env.ADMIN_PASSWORD, resetOn: process.env.ADMIN_RESET === "true", resetCodeInstalled: typeof resetAdmin === "function" });
    } catch (e) { return J({ status: "error", message: String((e && e.message) || e) }, 500); }
  }if (req.method !== "POST") return J({ error: "POST only" }, 405);
  let b; try { b = await req.json(); } catch { return J({ error: "bad json" }, 400); }
  const s = getStore({ name: "the-system", consistency: "strong" });
  const a = b.action;

  if (a === "salt") {
    await boot(s);
    const u = await byName(s, String(b.username || ""));
    return J({ salt: u ? u.salt : sign(await secret(s), "salt:" + b.username).slice(0, 8) });
  }
  if (a === "login") {
    await boot(s);
    const u = await byName(s, String(b.username || ""));
    if (!u || !same(u.ph, b.ph)) return J({ error: "bad credentials" }, 401);
    if (u.disabled) return J({ error: "disabled" }, 403);
    return J({ token: await token(s, u), ...(await snapshot(s, u)) });
  }
  if (a === "register") {
    const n = String(b.username || "");
    if (!NAME.test(n) || !goodStr(b.salt) || !goodStr(b.ph)) return J({ error: "invalid" }, 400);
    if (await byName(s, n)) return J({ error: "taken" }, 409);
    const u = { id: uid(), username: n, salt: b.salt, ph: b.ph, role: "user", created: Date.now(), disabled: false, defaultPw: false, survey: null, analysis: null, g: null };
    await putU(s, u);
    return J({ token: await token(s, u), ...(await snapshot(s, u)) });
  }

  const me = await auth(s, req);
  if (!me) return J({ error: "unauthorized" }, 401);
  const admin = me.role === "admin";

  if (a === "state") return J(await snapshot(s, me));

  if (a === "changePw") {
    if (!same(me.ph, b.oldPh) || !goodStr(b.salt) || !goodStr(b.ph)) return J({ error: "wrong password" }, 400);
    await putU(s, { ...me, salt: b.salt, ph: b.ph, defaultPw: false });
    return J({ ok: true });
  }

  if (a === "save") {
    const inc = Array.isArray(b.users) ? b.users : [];
    if (!admin) {
      const x = inc.find(u => u && u.id === me.id);
      if (!x) return J({ ok: true });
      if (JSON.stringify(x).length > 300000) return J({ error: "too large" }, 413);
      await putU(s, { ...me, survey: x.survey ?? null, analysis: x.analysis ?? null, g: x.g ?? null });
      return J({ ok: true });
    }
    const all = new Map((await loadAll(s)).map(u => [u.id, u]));
    const touched = new Set();
    for (const x of inc) {
      if (!x || !ID.test(x.id || "") || !NAME.test(x.username || "")) return J({ error: "invalid user" }, 400);
      const old = all.get(x.id);
      if (!old && !(goodStr(x.salt) && goodStr(x.ph))) return J({ error: "invalid user" }, 400);
      all.set(x.id, { ...(old || { id: x.id, created: Date.now() }),
        username: x.username, role: x.role === "admin" ? "admin" : "user", disabled: !!x.disabled, defaultPw: !!x.defaultPw,
        survey: x.survey ?? null, analysis: x.analysis ?? null, g: x.g ?? null,
        salt: goodStr(x.salt) ? x.salt : old.salt, ph: goodStr(x.ph) ? x.ph : old.ph });
      touched.add(x.id);
    }
    const gone = (Array.isArray(b.deleted) ? b.deleted : []).filter(id => ID.test(id) && id !== me.id && all.has(id));
    gone.forEach(id => all.delete(id));
    const names = new Set();
    for (const u of all.values()) { const k = u.username.toLowerCase(); if (names.has(k)) return J({ error: "taken" }, 409); names.add(k); }
    if (![...all.values()].some(u => u.role === "admin" && !u.disabled)) return J({ error: "need an active admin" }, 400);
    for (const id of touched) {
      const old = await getU(s, id), u = all.get(id);
      if (old && old.username.toLowerCase() !== u.username.toLowerCase()) await s.delete("name/" + old.username.toLowerCase());
      await putU(s, u);
    }
    for (const id of gone) { const old = await getU(s, id); if (old) await s.delete("name/" + old.username.toLowerCase()); await s.delete("u/" + id); }
    return J({ ok: true });
  }

  if (a === "export" && admin) return J({ users: await loadAll(s) });

  if (a === "import" && admin) {
    const us = Array.isArray(b.users) ? b.users : null;
    if (!us || !us.every(u => u && ID.test(u.id || "") && NAME.test(u.username || "") && goodStr(u.ph) && goodStr(u.salt)) ||
        !us.some(u => u.role === "admin" && !u.disabled)) return J({ error: "invalid backup" }, 400);
    const { blobs } = await s.list({ prefix: "name/" });
    await Promise.all(blobs.map(x => s.delete(x.key)));
    const old = await s.list({ prefix: "u/" });
    await Promise.all(old.blobs.map(x => s.delete(x.key)));
    for (const u of us) await putU(s, { ...u, role: u.role === "admin" ? "admin" : "user" });
    return J({ ok: true });
  }
  return J({ error: "unknown action" }, 400);
};

export const config = { path: "/api" };
