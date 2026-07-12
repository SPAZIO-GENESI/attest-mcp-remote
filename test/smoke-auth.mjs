// Phase-2 smoke test: device flow + attest_hash + create_certificate_pdf.
// LOCAL-ONLY harness: it needs an isolated imgauth `wrangler dev` (with its
// own --persist-to state) because the approval step is simulated by writing
// the local D1 directly — the real Turnstile approval path is exercised
// against production by the operator (see P26 design, FASE 2).
//
// Env (all required):
//   P26_MCP_BASE      e.g. http://127.0.0.1:8799
//   P26_IMGAUTH_BASE  e.g. http://127.0.0.1:8788
//   P26_IMGAUTH_DIR   local path of the imgauth repo (for wrangler d1 execute)
//   P26_PERSIST       the --persist-to dir of the isolated imgauth state
//   P26_API_KEY       a seeded sg_k_… credential in that isolated D1
//
// Usage: node test/smoke-auth.mjs

import { spawnSync } from "node:child_process";
import { writeFileSync, unlinkSync } from "node:fs";
import crypto from "node:crypto";

const MCP_BASE = need("P26_MCP_BASE");
const IMGAUTH_BASE = need("P26_IMGAUTH_BASE");
const IMGAUTH_DIR = need("P26_IMGAUTH_DIR");
const PERSIST = need("P26_PERSIST");
const API_KEY = need("P26_API_KEY");

function need(k) {
  const v = process.env[k];
  if (!v) {
    console.error(`Missing env ${k} — this is a local-only harness, see the header comment.`);
    process.exit(2);
  }
  return v;
}

if (!/^https?:\/\/(127\.0\.0\.1|localhost)[:/]/.test(IMGAUTH_BASE)) {
  console.error("Refusing to run: P26_IMGAUTH_BASE must be a local address (this harness writes the D1 directly).");
  process.exit(2);
}

// ── minimal MCP Streamable HTTP client ───────────────────────────────────────
class McpSession {
  constructor(base, extraHeaders = {}) {
    this.url = base.replace(/\/$/, "") + "/mcp";
    this.extraHeaders = extraHeaders;
    this.sessionId = null;
    this.nextId = 1;
  }
  async rpc(method, params, { notification = false } = {}) {
    const body = notification
      ? { jsonrpc: "2.0", method, params }
      : { jsonrpc: "2.0", id: this.nextId++, method, params };
    const headers = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...this.extraHeaders,
    };
    if (this.sessionId) headers["mcp-session-id"] = this.sessionId;
    const res = await fetch(this.url, { method: "POST", headers, body: JSON.stringify(body) });
    const sid = res.headers.get("mcp-session-id");
    if (sid) this.sessionId = sid;
    if (notification) {
      if (res.body) await res.body.cancel();
      return null;
    }
    if (!res.ok) throw new Error(`${method}: HTTP ${res.status} ${await res.text()}`);
    const ctype = res.headers.get("content-type") || "";
    if (ctype.includes("text/event-stream")) {
      const raw = await res.text();
      let result = null;
      for (const line of raw.split("\n")) {
        if (!line.startsWith("data:")) continue;
        try {
          const msg = JSON.parse(line.slice(5).trim());
          if (msg.id === body.id) result = msg;
        } catch {
          /* ignore */
        }
      }
      if (!result) throw new Error(`${method}: no JSON-RPC response in SSE stream`);
      return result;
    }
    return await res.json();
  }
  async start() {
    await this.rpc("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "smoke-auth", version: "0.0.1" },
    });
    await this.rpc("notifications/initialized", {}, { notification: true });
  }
  async call(name, args) {
    const msg = await this.rpc("tools/call", { name, arguments: args ?? {} });
    if (msg.error) return { protocolError: msg.error };
    return msg.result;
  }
}

const t = (r) => r?.content?.find((c) => c.type === "text")?.text ?? "";

let failures = 0;
function check(label, cond, detail) {
  if (cond) console.log(`  ok  ${label}`);
  else {
    failures++;
    console.log(`FAIL  ${label}${detail ? " — " + String(detail).slice(0, 300) : ""}`);
  }
}

// Simulated approval: what the Turnstile-guarded /api/agent/approve would do,
// written straight into the isolated local D1.
function approveInLocalD1(code) {
  const id = crypto.randomBytes(4).toString("hex");
  const secret = crypto.randomBytes(32).toString("base64url");
  const token = `sg_s_${id}_${secret}`;
  const secretHash = crypto.createHash("sha256").update(secret).digest("hex");
  const now = Date.now();
  const sql =
    `INSERT INTO agent_credentials (id, kind, secret_hash, label, quota, used, period, expires_at, revoked, created_at) ` +
    `VALUES ('${id}', 'session', '${secretHash}', 'session', 20, 0, NULL, ${now + 24 * 3600 * 1000}, 0, '${new Date(now).toISOString()}'); ` +
    `UPDATE agent_authorizations SET status = 'approved', token_once = '${token}', credential_id = '${id}' WHERE code = '${code}';`;
  // SQL via temp file: on Windows, spawnSync with shell:true mangles a
  // --command argument containing spaces/quotes.
  const sqlFile = `${PERSIST}\\approve-${code}.sql`;
  writeFileSync(sqlFile, sql);
  const r = spawnSync(
    "npx.cmd",
    ["wrangler", "d1", "execute", "imgauth-health", "--local", "--persist-to", PERSIST, "--file", sqlFile],
    { cwd: IMGAUTH_DIR, shell: true, encoding: "utf8", timeout: 120000 }
  );
  try { unlinkSync(sqlFile); } catch { /* ignore */ }
  if (r.status !== 0) throw new Error(`d1 approve failed: ${r.stderr?.slice(0, 400)}`);
}

// A fresh, never-attested fingerprint with a known preimage.
const workBytes = crypto.randomBytes(1024);
const workHash = crypto.createHash("sha256").update(workBytes).digest("hex");

// ── Session A: full device flow ──────────────────────────────────────────────
console.log("Session A — device flow end-to-end");
const A = new McpSession(MCP_BASE);
await A.start();

const auth = await A.call("authorize");
const code = (t(auth).match(/code=([0-9a-f]{16})/) || [])[1];
check("authorize returns a verification link with a code", !!code, t(auth));

{
  const r = await A.call("complete_authorization");
  check("complete_authorization before approval → not approved yet", /Not approved yet/i.test(t(r)), t(r));
}

approveInLocalD1(code);
console.log("  (approval simulated in local D1)");

{
  const r = await A.call("complete_authorization");
  const txt = t(r);
  check("complete_authorization after approval → complete, token NOT echoed", /Authorization complete/.test(txt) && !/sg_s_/.test(txt), txt);
}

{
  const r = await A.call("attest_hash", { sha256: workHash, name: "opera-test.bin", titolo: "Opera di prova P26" });
  const txt = t(r);
  check("attest_hash → attestazione + hmac", new RegExp(`SHA-256:${workHash}@`).test(txt) && /hmac \(server signature\): .+=/.test(txt), txt);
  globalThis.__att = txt;
}

{
  const r = await A.call("create_certificate_pdf", { sha256: workHash });
  check("create_certificate_pdf → permanent links", /Certificate generated and archived/.test(t(r)) && t(r).includes(`/c/${workHash}`), t(r));
}

{
  const res = await fetch(`${IMGAUTH_BASE}/api/cert?hash=${workHash}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  const isPdf = res.status === 200 && buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46;
  check("PDF really archived and retrievable from /api/cert", isPdf, `status=${res.status} bytes=${buf.length}`);
}

{
  // Round-trip: the attestation issued above must verify via the public tool.
  const att = globalThis.__att.match(/attestazione: (\S+)/)[1];
  const hmac = globalThis.__att.match(/hmac \(server signature\): (\S+)/)[1];
  const r = await A.call("verify_attestation", { sha256: workHash, attestazione: att, hmac, titolo: "Opera di prova P26" });
  check("verify_attestation on the fresh attestation → SIGNATURE VALID", /SIGNATURE VALID/.test(t(r)), t(r));
}

// ── Session B: fresh session, no credential ──────────────────────────────────
console.log("Session B — no credential");
const B = new McpSession(MCP_BASE);
await B.start();
{
  const r = await B.call("attest_hash", { sha256: workHash });
  check("attest_hash without credential → guidance error", r.isError === true && /authorize/.test(t(r)), t(r));
}
{
  const r = await B.call("complete_authorization");
  check("complete_authorization without authorize → error", r.isError === true && /authorize/i.test(t(r)), t(r));
}

// ── Session C: API key via Authorization header ──────────────────────────────
console.log("Session C — header pass-through (sg_k)");
const C = new McpSession(MCP_BASE, { authorization: `Bearer ${API_KEY}` });
await C.start();
{
  const freshHash = crypto.createHash("sha256").update(crypto.randomBytes(512)).digest("hex");
  const r = await C.call("attest_hash", { sha256: freshHash });
  check("attest_hash with header credential, no device flow", new RegExp(`SHA-256:${freshHash}@`).test(t(r)), t(r));
}
{
  const r = await C.call("authorize");
  check("authorize with header credential → says not needed", /already available/.test(t(r)), t(r));
}

console.log(failures === 0 ? "\nALL GREEN" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
