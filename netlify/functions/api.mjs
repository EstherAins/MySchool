import { getDatabase } from "@netlify/database";
import { scrypt, randomBytes, timingSafeEqual, createHash } from "node:crypto";
import { promisify } from "node:util";

const sc = promisify(scrypt);
const json = (d, s = 200, h = {}) =>
  new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json", ...h } });
const hashPw = async (p) => { const s = randomBytes(16); const k = await sc(p, s, 64); return s.toString("hex") + ":" + k.toString("hex"); };
const checkPw = async (p, st) => { const [s, h] = st.split(":"); const k = await sc(p, Buffer.from(s, "hex"), 64); return timingSafeEqual(k, Buffer.from(h, "hex")); };
const sha = (t) => createHash("sha256").update(t).digest("hex");
const pub = (u) => ({ email: u.email, name: u.name, cls: u.class, addr: u.address, av: u.gender });
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export default async (req) => {
  const db = await getDatabase();
  const q = async (t, p) => (await db.pool.query(t, p)).rows;
  const path = new URL(req.url).pathname.replace(/^\/api/, "");
  const m = req.method;
  let b = {};
  if (m !== "GET" && m !== "DELETE") { try { b = await req.json(); } catch {} }
  const ck = Object.fromEntries((req.headers.get("cookie") || "").split(/;\s*/).filter(Boolean).map((c) => { const i = c.indexOf("="); return [c.slice(0, i), c.slice(i + 1)]; }));
  const me = async () => {
    if (!ck.sid) return null;
    return (await q("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()", [sha(ck.sid)]))[0] || null;
  };
  const session = async (uid, remember) => {
    const t = randomBytes(32).toString("hex");
    await q("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 days')", [sha(t), uid]);
    return `sid=${t}; HttpOnly; Secure; SameSite=Lax; Path=/${remember ? "; Max-Age=2592000" : ""}`;
  };
  try {
    if (path === "/register" && m === "POST") {
      const email = String(b.email || "").trim().toLowerCase(), name = String(b.name || "").trim();
      if (!EMAIL.test(email)) return json({ error: "Email i pavlefshëm." }, 400);
      if (String(b.password || "").length < 8) return json({ error: "Fjalëkalimi duhet të ketë të paktën 8 karaktere." }, 400);
      if (name.length < 2) return json({ error: "Shkruaj emrin e plotë." }, 400);
      if (!["boy", "girl"].includes(b.gender)) return json({ error: "Zgjidh gjininë." }, 400);
      const r = await q("INSERT INTO users(email,name,class,address,gender,pass_hash) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(email) DO NOTHING RETURNING *",
        [email, name.slice(0, 80), String(b.cls || "—").slice(0, 20) || "—", String(b.addr || "").slice(0, 200), b.gender, await hashPw(b.password)]);
      if (!r[0]) return json({ error: "Ky email është i regjistruar tashmë." }, 409);
      return json({ user: pub(r[0]) }, 201, { "Set-Cookie": await session(r[0].id, true) });
    }
    if (path === "/login" && m === "POST") {
      const u = (await q("SELECT * FROM users WHERE email=$1", [String(b.email || "").trim().toLowerCase()]))[0];
      if (!u || !(await checkPw(String(b.password || ""), u.pass_hash))) return json({ error: "Emaili ose fjalëkalimi është i pasaktë." }, 401);
      return json({ user: pub(u) }, 200, { "Set-Cookie": await session(u.id, !!b.remember) });
    }
    if (path === "/logout" && m === "POST") {
      if (ck.sid) await q("DELETE FROM sessions WHERE token_hash=$1", [sha(ck.sid)]);
      return json({ ok: true }, 200, { "Set-Cookie": "sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" });
    }
    const u = await me();
    if (!u) return json({ error: "Nuk je i kyçur." }, 401);
    if (path === "/me" && m === "GET") return json({ user: pub(u) });
    if (path === "/me" && m === "PATCH") {
      const name = String(b.name || "").trim();
      if (name.length < 2) return json({ error: "Shkruaj emrin e plotë." }, 400);
      const r = await q("UPDATE users SET name=$1,class=$2,address=$3 WHERE id=$4 RETURNING *",
        [name.slice(0, 80), String(b.cls || "—").slice(0, 20) || "—", String(b.addr || "").slice(0, 200), u.id]);
      return json({ user: pub(r[0]) });
    }
    if (path === "/data" && m === "GET") {
      const hw = await q("SELECT id,title AS t,done AS on FROM homework WHERE user_id=$1 ORDER BY id", [u.id]);
      const rd = await q("SELECT notice_id FROM notice_reads WHERE user_id=$1", [u.id]);
      return json({ homework: hw, reads: rd.map((x) => x.notice_id) });
    }
    if (path === "/homework" && m === "POST") {
      const t = String(b.title || "").trim().slice(0, 200);
      if (!t) return json({ error: "Shkruaj detyrën." }, 400);
      return json({ id: (await q("INSERT INTO homework(user_id,title) VALUES($1,$2) RETURNING id", [u.id, t]))[0].id }, 201);
    }
    const hm = path.match(/^\/homework\/(\d+)$/);
    if (hm && m === "PATCH") { await q("UPDATE homework SET done=$1 WHERE id=$2 AND user_id=$3", [!!b.done, +hm[1], u.id]); return json({ ok: true }); }
    if (hm && m === "DELETE") { await q("DELETE FROM homework WHERE id=$1 AND user_id=$2", [+hm[1], u.id]); return json({ ok: true }); }
    if (path === "/notices/read" && m === "POST") {
      const ids = (Array.isArray(b.ids) ? b.ids : []).map(Number).filter(Number.isInteger).slice(0, 100);
      if (ids.length) await q("INSERT INTO notice_reads(user_id,notice_id) SELECT $1, unnest($2::int[]) ON CONFLICT DO NOTHING", [u.id, ids]);
      return json({ ok: true });
    }
    return json({ error: "Nuk u gjet." }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: "Gabim në server." }, 500);
  }
};
export const config = { path: "/api/*" };
