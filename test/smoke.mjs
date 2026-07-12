// Smoke test for the remote MCP server: drives the Streamable HTTP transport
// directly (initialize → initialized → tools/list → tools/call) against a
// running instance (default: wrangler dev on http://localhost:8787/mcp).
//
// Public-tool cases only (phase 1). The "valid signature" fixture uses the
// GTF dogfooding-anchor certificate: PUBLIC data by design (printed on a
// certificate reachable by its fingerprint — same data class as the HMAC
// canary in imgauth's monitor).
//
// Usage: node test/smoke.mjs [base-url]

const BASE = process.argv[2] || "http://localhost:8787";
const MCP = BASE.replace(/\/$/, "") + "/mcp";

// Fixtures (public): GTF dogfooding anchor, attested 2026-07-09.
const ATTESTED = {
  hash: "cd57b5d3a96947a2264cbb237b3c8eb26cb130e2703838e0597d7b3189e5629b",
  attestazione:
    "SHA-256:cd57b5d3a96947a2264cbb237b3c8eb26cb130e2703838e0597d7b3189e5629b@2026-07-09T14:40:06Z",
  hmac: "agHk0031RtnbFxTxugLiAC37vOAYJwrr0/Rw8RbG2Zk=",
};
const UNKNOWN_HASH = "1".repeat(64); // valid hex, (astronomically) never attested

let sessionId = null;
let nextId = 1;

async function rpc(method, params, { notification = false } = {}) {
  const body = notification
    ? { jsonrpc: "2.0", method, params }
    : { jsonrpc: "2.0", id: nextId++, method, params };
  const headers = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const res = await fetch(MCP, { method: "POST", headers, body: JSON.stringify(body) });
  const sid = res.headers.get("mcp-session-id");
  if (sid) sessionId = sid;
  if (notification) {
    if (res.body) await res.body.cancel();
    return null;
  }
  if (!res.ok) throw new Error(`${method}: HTTP ${res.status} ${await res.text()}`);
  const ctype = res.headers.get("content-type") || "";
  if (ctype.includes("text/event-stream")) {
    const raw = await res.text();
    // Take the last data: line carrying a JSON-RPC response with our id.
    let result = null;
    for (const line of raw.split("\n")) {
      if (!line.startsWith("data:")) continue;
      try {
        const msg = JSON.parse(line.slice(5).trim());
        if (msg.id === body.id) result = msg;
      } catch {
        /* non-JSON data line */
      }
    }
    if (!result) throw new Error(`${method}: no JSON-RPC response in SSE stream`);
    return result;
  }
  return await res.json();
}

async function callTool(name, args) {
  const msg = await rpc("tools/call", { name, arguments: args ?? {} });
  if (msg.error) return { protocolError: msg.error };
  return msg.result;
}

function firstText(result) {
  return result?.content?.find((c) => c.type === "text")?.text ?? "";
}

let failures = 0;
function check(label, cond, detail) {
  if (cond) console.log(`  ok  ${label}`);
  else {
    failures++;
    console.log(`FAIL  ${label}${detail ? " — " + String(detail).slice(0, 300) : ""}`);
  }
}

// ── handshake ────────────────────────────────────────────────────────────────
const init = await rpc("initialize", {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "smoke", version: "0.0.1" },
});
check("initialize", !!init.result?.serverInfo, JSON.stringify(init).slice(0, 200));
await rpc("notifications/initialized", {}, { notification: true });

// ── tools/list ───────────────────────────────────────────────────────────────
const list = await rpc("tools/list", {});
const toolNames = (list.result?.tools ?? []).map((t) => t.name).sort();
check(
  "tools/list has the 4 public tools",
  JSON.stringify(toolNames) ===
    JSON.stringify(["check_anchor", "lookup_certificate", "service_status", "verify_attestation"]),
  toolNames.join(",")
);

// ── service_status ───────────────────────────────────────────────────────────
{
  const r = await callTool("service_status");
  const t = firstText(r);
  check("service_status reports components", /worker.*archive.*signer.*anchor/s.test(t), t);
}

// ── check_anchor ─────────────────────────────────────────────────────────────
{
  const r = await callTool("check_anchor", { sha256: ATTESTED.hash });
  check("check_anchor: attested hash → proof EXISTS", /proof EXISTS/.test(firstText(r)), firstText(r));
}
{
  const r = await callTool("check_anchor", { sha256: UNKNOWN_HASH });
  check("check_anchor: unknown hash → no proof", /No OpenTimestamps proof/.test(firstText(r)), firstText(r));
}
{
  const r = await callTool("check_anchor", { sha256: "not-a-hash" });
  const t = firstText(r) + JSON.stringify(r.protocolError ?? "");
  check(
    "check_anchor: malformed hash → local error, no upstream call",
    r.isError === true || /Invalid sha256|invalid_string|regex|64 hex/i.test(t),
    t
  );
}

// ── lookup_certificate ───────────────────────────────────────────────────────
{
  const r = await callTool("lookup_certificate", { sha256: ATTESTED.hash });
  const t = firstText(r);
  check("lookup_certificate: attested hash → links", /IS attested/.test(t) && t.includes(`/c/${ATTESTED.hash}`), t);
}
{
  const r = await callTool("lookup_certificate", { sha256: UNKNOWN_HASH });
  check("lookup_certificate: unknown hash → not found", /No certificate found/.test(firstText(r)), firstText(r));
}

// ── verify_attestation ───────────────────────────────────────────────────────
const ATTESTED_ARGS = { sha256: ATTESTED.hash, attestazione: ATTESTED.attestazione, hmac: ATTESTED.hmac };
{
  const r = await callTool("verify_attestation", ATTESTED_ARGS);
  check("verify_attestation: real certificate → SIGNATURE VALID", /SIGNATURE VALID/.test(firstText(r)), firstText(r));
}
{
  const tampered = { ...ATTESTED_ARGS, hmac: (ATTESTED.hmac[0] === "a" ? "b" : "a") + ATTESTED.hmac.slice(1) };
  const r = await callTool("verify_attestation", tampered);
  check("verify_attestation: tampered hmac → SIGNATURE INVALID", /SIGNATURE INVALID/.test(firstText(r)), firstText(r));
}
{
  const r = await callTool("verify_attestation", { ...ATTESTED_ARGS, sha256: UNKNOWN_HASH });
  check(
    "verify_attestation: sha256/attestazione mismatch → local error",
    r.isError === true && /do not match/.test(firstText(r)),
    firstText(r)
  );
}

console.log(failures === 0 ? "\nALL GREEN" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
