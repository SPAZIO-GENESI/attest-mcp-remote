// attest-mcp-remote — remote MCP server (Streamable HTTP) for the Spazio
// Genesi digital-work attestation service (https://attestazione.spaziogenesi.org).
//
// Design (binding: img-auth-hub/P26-DESIGN-mcp-remoto.md):
// - Pure client of the public imgauth API. No imgauth changes, no secrets.
// - Hash-based by protocol necessity AND by privacy choice: MCP has no
//   reliable client→server file channel (tool arguments travel through the
//   model context), so tools take a SHA-256 fingerprint — the file never
//   transits, not even through this server.
// - Public tools (this phase): service_status, check_anchor,
//   verify_attestation, lookup_certificate. Credentialed tools (device
//   flow / attest_hash) arrive in a later phase.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";

const DEFAULT_API_BASE = "https://imgauth.spaziogenesi.org";
const SITE_BASE = "https://attestazione.spaziogenesi.org";
const FETCH_TIMEOUT_MS = 15_000;

// Configurable for local testing against a wrangler-dev imgauth
// (env.IMGAUTH_BASE); production needs no var and uses the default —
// same pattern as imgauth's ALLOWED_ORIGIN. Set at both entry points
// (worker fetch and Durable Object init), since they may run in
// different isolates.
let activeApiBase = DEFAULT_API_BASE;

const SHA256_RE = /^[A-Fa-f0-9]{64}$/;

const HASH_HOWTO =
  "Compute the SHA-256 locally if you have code execution " +
  "(`sha256sum <file>` / `shasum -a 256 <file>` / `certutil -hashfile <file> SHA256`). " +
  "NEVER send file bytes or base64 through tool arguments: this server never receives files. " +
  "If you cannot compute a hash locally, point the user to the website " +
  "(https://attestazione.spaziogenesi.org, full privacy: hashing happens in the browser) " +
  "or the Telegram bot @SGAttestBot.";

const sha256Param = z
  .string()
  .describe("SHA-256 fingerprint of the work: 64 hexadecimal characters. " + HASH_HOWTO);

function normalizeHash(raw) {
  const h = String(raw ?? "").trim().toLowerCase();
  return SHA256_RE.test(h) ? h : null;
}

function text(t) {
  return { content: [{ type: "text", text: t }] };
}

function toolError(t) {
  return { content: [{ type: "text", text: t }], isError: true };
}

function badHashError() {
  return toolError(
    "Invalid sha256: expected exactly 64 hexadecimal characters. No request was sent to the service. " + HASH_HOWTO
  );
}

async function apiFetch(path, init = {}) {
  return fetch(activeApiBase + path, {
    ...init,
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
}

// Discard a response body we don't need (frees the connection in Workers).
async function drop(res) {
  if (res.body) {
    try {
      await res.body.cancel();
    } catch {
      /* ignore */
    }
  }
}

function upstreamError(res, what) {
  if (res.status === 429) {
    return toolError(
      `The attestation service is rate-limiting requests right now (${what}). Wait about a minute, then retry once — do not retry aggressively.`
    );
  }
  return toolError(`The attestation service answered HTTP ${res.status} (${what}). This is a service-side condition, not a problem with your input.`);
}

function certificateLinks(hash) {
  return [
    `- Public certificate page: ${SITE_BASE}/c/${hash}`,
    `- Certificate PDF: ${activeApiBase}/api/cert?hash=${hash}`,
    `- OpenTimestamps proof (.ots): ${activeApiBase}/api/ots?hash=${hash}`,
    `- Verify with the file in the browser: ${SITE_BASE}?hash=${hash}`,
  ].join("\n");
}

// Bearer credential shape issued by the service (API key sg_k_… or
// device-flow session token sg_s_…). Mirrors imgauth's BEARER_RE.
const CREDENTIAL_RE = /^sg_(k|s)_[0-9a-f]{8,32}_[A-Za-z0-9_-]{16,64}$/;

export class AttestMcpAgent extends McpAgent {
  server = new McpServer({
    name: "spazio-genesi-attestation",
    version: "1.0.0",
  });

  // Session state (Durable Object storage, scoped to this MCP session):
  // - pendingAuth: device-flow request awaiting user approval
  // - token: claimed session token (sg_s_…, 24h TTL). NEVER logged, never
  //   echoed in tool results after the claim.
  // - lastAttestation: the /api/hash response, kept so
  //   create_certificate_pdf can be called with just the fingerprint.
  initialState = { pendingAuth: null, token: null, lastAttestation: null };

  // Credential resolution order: explicit Authorization header on the /mcp
  // request (power users, e.g. Claude Code --header) wins over the
  // device-flow session token.
  resolveCredential() {
    const headerBearer = this.props?.bearer;
    if (headerBearer) return headerBearer;
    const t = this.state.token;
    if (t && Date.now() < t.expiresAt) return t.value;
    return null;
  }

  noCredentialError() {
    return toolError(
      [
        "No valid credential for attestation. Two options:",
        "1. Device flow (no configuration): call the `authorize` tool, have the user open the link and approve, then call `complete_authorization`.",
        "2. API key: connect with an `Authorization: Bearer sg_k_…` header (e.g. Claude Code: `claude mcp add --transport http … --header \"Authorization: Bearer sg_k_…\"`). Keys: https://imgauth.spaziogenesi.org/developer/keys",
        "Verification tools need no credential.",
      ].join("\n")
    );
  }

  async init() {
    activeApiBase = this.env?.IMGAUTH_BASE || DEFAULT_API_BASE;
    this.server.registerTool(
      "service_status",
      {
        description:
          "Health of the Spazio Genesi attestation service components: worker (attestation engine), " +
          "archive (certificate storage), signer (PDF cryptographic signature), anchor (Bitcoin/OpenTimestamps calendars). " +
          "Values: ok | degraded | down | n/d.",
        inputSchema: {},
      },
      async () => {
        let res;
        try {
          res = await apiFetch("/api/status");
        } catch {
          return toolError("Could not reach the attestation service (network error or timeout).");
        }
        if (!res.ok) return upstreamError(res, "GET /api/status");
        const s = await res.json();
        const lines = [
          `Attestation service status (checked_at: ${s.checked_at ?? "n/d"}):`,
          `- worker (attestation engine): ${s.worker ?? "n/d"}`,
          `- archive (certificate storage): ${s.archive ?? "n/d"}`,
          `- signer (PDF signature): ${s.signer ?? "n/d"}`,
          `- anchor (Bitcoin/OpenTimestamps): ${s.anchor ?? "n/d"}`,
          "",
          `Live status page: ${SITE_BASE}/status/`,
        ];
        return text(lines.join("\n"));
      }
    );

    this.server.registerTool(
      "check_anchor",
      {
        description:
          "Check whether a work's SHA-256 fingerprint has an OpenTimestamps proof anchored in Bitcoin. " +
          "The proof is created at attestation time and matures (pending → Bitcoin-confirmed) within a few hours.",
        inputSchema: { sha256: sha256Param },
      },
      async ({ sha256 }) => {
        const hash = normalizeHash(sha256);
        if (!hash) return badHashError();
        let res;
        try {
          res = await apiFetch(`/api/ots?hash=${hash}`);
        } catch {
          return toolError("Could not reach the attestation service (network error or timeout).");
        }
        await drop(res);
        if (res.status === 200) {
          return text(
            [
              `An OpenTimestamps proof EXISTS for ${hash}.`,
              "",
              `- Download the proof: ${activeApiBase}/api/ots?hash=${hash}`,
              "- The proof may still be 'pending' if the attestation is recent; it matures with Bitcoin confirmation within a few hours.",
              "- Anyone can verify or upgrade it independently at https://opentimestamps.org or with the `ots` client.",
            ].join("\n")
          );
        }
        if (res.status === 404) {
          return text(
            `No OpenTimestamps proof found for ${hash}. Either this fingerprint was never attested, or it was attested while the OpenTimestamps calendars were unreachable (the service fails open).`
          );
        }
        return upstreamError(res, "GET /api/ots");
      }
    );

    this.server.registerTool(
      "verify_attestation",
      {
        description:
          "Verify the server HMAC signature of an attestation issued by the Spazio Genesi service. " +
          "Confirms that the attestation string (fingerprint + timestamp) and any declared metadata are authentic and untampered. " +
          "Note: this checks the SIGNATURE only. Whether a given file matches the fingerprint must be checked locally by re-hashing the file. " +
          "If the certificate carried declared metadata (title/author/year/notes), they must be provided EXACTLY as printed for the signature to verify.",
        inputSchema: {
          sha256: sha256Param,
          attestazione: z
            .string()
            .describe('The attestation string exactly as printed on the certificate: "SHA-256:<hash>@<ISO timestamp>Z"'),
          hmac: z
            .string()
            .describe("The server HMAC signature exactly as printed on the certificate (base64, 44 characters ending with '=')."),
          titolo: z.string().optional().describe("Declared title, exactly as printed (only if the certificate shows it)."),
          autore: z.string().optional().describe("Declared author, exactly as printed (only if the certificate shows it)."),
          anno: z.string().optional().describe("Declared year/version, exactly as printed (only if the certificate shows it)."),
          note: z.string().optional().describe("Declared notes, exactly as printed (only if the certificate shows them)."),
        },
      },
      async ({ sha256, attestazione, hmac, titolo, autore, anno, note }) => {
        const hash = normalizeHash(sha256);
        if (!hash) return badHashError();
        const att = String(attestazione ?? "").trim();
        // Free local sanity check: the attestation string embeds the hash.
        // A mismatch can never verify, so don't waste a service call.
        const m = att.match(/^SHA-256:([A-Fa-f0-9]{64})@(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$/);
        if (!m) {
          return toolError(
            'Malformed attestazione: expected "SHA-256:<64 hex chars>@<YYYY-MM-DDTHH:MM:SSZ>". No request was sent to the service.'
          );
        }
        if (m[1].toLowerCase() !== hash) {
          return toolError(
            "The sha256 argument and the hash inside the attestazione string do not match. No request was sent to the service."
          );
        }
        const form = new FormData();
        form.set("hash", hash);
        form.set("attestazione", att);
        form.set("hmac", String(hmac ?? "").trim());
        if (titolo) form.set("titolo", titolo);
        if (autore) form.set("autore", autore);
        if (anno) form.set("anno", anno);
        if (note) form.set("note", note);
        let res;
        try {
          res = await apiFetch("/api/verify", { method: "POST", body: form });
        } catch {
          return toolError("Could not reach the attestation service (network error or timeout).");
        }
        if (!res.ok) return upstreamError(res, "POST /api/verify");
        const v = await res.json();
        if (v.hmac_valido === true) {
          return text(
            [
              `SIGNATURE VALID. The attestation for ${hash} is authentic:`,
              `- the fingerprint and its server timestamp (${m[2]}) were really issued by the service and are untampered;`,
              "- any declared metadata provided here are bound by the signature and untampered.",
              "",
              "Remember: to confirm a FILE matches this fingerprint, re-hash the file locally and compare.",
            ].join("\n")
          );
        }
        if (v.hmac_valido === false) {
          return text(
            [
              `SIGNATURE INVALID for ${hash}.`,
              "The attestation string, the HMAC, or the declared metadata do not match what the service signed.",
              "Common causes: a typo in a copied value, metadata not provided exactly as printed, or a tampered certificate.",
            ].join("\n")
          );
        }
        return text(
          "The service could not evaluate the signature (hmac_valido: null) — the HMAC verification is not configured server-side right now. Try again later or check service_status."
        );
      }
    );

    this.server.registerTool(
      "lookup_certificate",
      {
        description:
          "Look up whether a work's SHA-256 fingerprint has an attestation certificate in the public archive, " +
          "and get its permanent links (public certificate page, PDF download, OpenTimestamps proof, browser verification). " +
          "Trust model: this information is reachable only by whoever knows the fingerprint.",
        inputSchema: { sha256: sha256Param },
      },
      async ({ sha256 }) => {
        const hash = normalizeHash(sha256);
        if (!hash) return badHashError();
        let res;
        try {
          res = await apiFetch(`/c/${hash}`);
        } catch {
          return toolError("Could not reach the attestation service (network error or timeout).");
        }
        await drop(res);
        if (res.status === 200) {
          return text([`Work ${hash} IS attested. Permanent links:`, "", certificateLinks(hash)].join("\n"));
        }
        if (res.status === 404) {
          return text(
            `No certificate found in the archive for ${hash}. Notes: certificates issued before v1.8.0 (June 2026) are not retrievable by fingerprint; a certificate appears here after the PDF has been generated and archived.`
          );
        }
        return upstreamError(res, "GET /c/<hash>");
      }
    );

    // ── Credentialed tools (device flow → attest → certificate) ────────────

    this.server.registerTool(
      "authorize",
      {
        description:
          "Start the device-flow authorization to attest works in this session (up to 20 attestations, 24h). " +
          "Returns a link the USER must open in a browser and approve (anti-bot check included). " +
          "After the user approves, call `complete_authorization`. " +
          "Not needed if the connection already carries an API key header, or for verification tools.",
        inputSchema: {},
      },
      async () => {
        if (this.resolveCredential()) {
          return text("A valid credential is already available in this session — you can call attest_hash directly.");
        }
        let res;
        try {
          res = await apiFetch("/api/agent/authorize", { method: "POST" });
        } catch {
          return toolError("Could not reach the attestation service (network error or timeout).");
        }
        if (!res.ok) return upstreamError(res, "POST /api/agent/authorize");
        const a = await res.json();
        this.setState({
          ...this.state,
          pendingAuth: {
            code: a.code,
            interval: Number(a.interval) || 3,
            expiresAt: Date.now() + (Number(a.expires_in) || 600) * 1000,
          },
        });
        return text(
          [
            "Authorization started. Show this link to the USER and ask them to open it in a browser and approve:",
            "",
            a.verification_url,
            "",
            `The request expires in ${Math.floor((Number(a.expires_in) || 600) / 60)} minutes.`,
            "Once the user says they approved, call `complete_authorization`.",
          ].join("\n")
        );
      }
    );

    this.server.registerTool(
      "complete_authorization",
      {
        description:
          "Complete the device-flow authorization after the user approved in the browser. " +
          "Polls the service briefly; if approval hasn't happened yet, just call this tool again.",
        inputSchema: {},
      },
      async () => {
        const pa = this.state.pendingAuth;
        if (!pa) return toolError("No authorization in progress. Call `authorize` first.");
        if (Date.now() > pa.expiresAt) {
          this.setState({ ...this.state, pendingAuth: null });
          return toolError("The authorization request expired. Call `authorize` again to start over.");
        }
        const intervalMs = Math.max(1, pa.interval) * 1000;
        for (let attempt = 0; attempt < 5; attempt++) {
          if (attempt > 0) await new Promise((r) => setTimeout(r, intervalMs));
          let res;
          try {
            res = await apiFetch(`/api/agent/token?code=${pa.code}`);
          } catch {
            return toolError("Could not reach the attestation service (network error or timeout). Call this tool again.");
          }
          if (res.status === 410) {
            await drop(res);
            this.setState({ ...this.state, pendingAuth: null });
            return toolError("The authorization request expired. Call `authorize` again to start over.");
          }
          if (!res.ok) return upstreamError(res, "GET /api/agent/token");
          const t = await res.json();
          if (t.status === "pending") continue;
          if (t.status === "approved" && t.token) {
            // Claimed exactly once. Conservative local expiry: the real TTL
            // is 24h from approval; 23h avoids using a token about to die.
            this.setState({
              ...this.state,
              pendingAuth: null,
              token: { value: t.token, expiresAt: Date.now() + 23 * 60 * 60 * 1000 },
            });
            return text(
              "Authorization complete. This session can now attest (up to 20 attestations, 24h). Call `attest_hash` with the work's SHA-256."
            );
          }
          if (t.status === "claimed") {
            this.setState({ ...this.state, pendingAuth: null });
            return toolError(
              "This authorization was already claimed (possibly by another session) and can't be reused. Call `authorize` again."
            );
          }
        }
        return text(
          "Not approved yet. Ask the user to open the authorization link and approve, then call `complete_authorization` again."
        );
      }
    );

    this.server.registerTool(
      "attest_hash",
      {
        description:
          "Attest a work: the service binds the SHA-256 fingerprint to a server-side timestamp and signs it (HMAC). " +
          "Requires a credential (device flow via `authorize`, or an API key header). " +
          "Optional declared metadata (title/author/year/notes) are normalized and BOUND by the signature — immutable after issuance, " +
          "but they remain self-declared (they don't prove authorship). " +
          HASH_HOWTO,
        inputSchema: {
          sha256: sha256Param,
          name: z.string().optional().describe("File name (descriptive only, shown on the certificate)."),
          size: z.number().int().positive().optional().describe("File size in bytes (descriptive only)."),
          type: z.string().optional().describe("MIME type (descriptive only)."),
          titolo: z.string().optional().describe("Declared title of the work (bound by the signature)."),
          autore: z.string().optional().describe("Declared author (bound by the signature)."),
          anno: z.string().optional().describe("Declared year/version (bound by the signature)."),
          note: z.string().optional().describe("Declared notes (bound by the signature)."),
        },
      },
      async ({ sha256, name, size, type, titolo, autore, anno, note }) => {
        const hash = normalizeHash(sha256);
        if (!hash) return badHashError();
        const credential = this.resolveCredential();
        if (!credential) return this.noCredentialError();

        const payload = { sha256: hash };
        if (name) payload.name = name;
        if (size) payload.size = size;
        if (type) payload.type = type;
        if (titolo) payload.titolo = titolo;
        if (autore) payload.autore = autore;
        if (anno) payload.anno = anno;
        if (note) payload.note = note;

        let res;
        try {
          res = await apiFetch("/api/hash", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${credential}`,
            },
            body: JSON.stringify(payload),
          });
        } catch {
          return toolError("Could not reach the attestation service (network error or timeout).");
        }
        if (res.status === 403) {
          await drop(res);
          // A session token that stopped working is dead (revoked/expired):
          // drop it so the next attempt asks to authorize again.
          if (!this.props?.bearer && this.state.token) {
            this.setState({ ...this.state, token: null });
          }
          return toolError("Credential rejected (invalid, revoked or expired). Run `authorize` again, or check the API key in the connection header.");
        }
        if (res.status === 429) {
          await drop(res);
          return toolError(
            "Rejected: either the credential's attestation quota is exhausted, or the service is rate-limiting. If you just authorized, the quota (20 per session) may be used up — otherwise wait a minute and retry once."
          );
        }
        if (!res.ok) return upstreamError(res, "POST /api/hash");
        const att = await res.json();
        this.setState({ ...this.state, lastAttestation: att });
        return text(
          [
            `Attested. The service bound fingerprint ${att.sha256} to its server timestamp:`,
            `- attestazione: ${att.attestazione}`,
            `- timestamp: ${att.timestamp_iso}`,
            `- hmac (server signature): ${att.hmac}`,
            att.titolo || att.autore || att.anno || att.note
              ? `- declared metadata bound by the signature: ${["titolo", "autore", "anno", "note"].filter((k) => att[k]).map((k) => `${k}="${att[k]}"`).join(", ")}`
              : null,
            "",
            "IMPORTANT: report these values to the user (they are the proof). Then call `create_certificate_pdf` with the same sha256 to generate and archive the certificate PDF (adds Bitcoin anchoring and permanent links).",
          ]
            .filter((l) => l !== null)
            .join("\n")
        );
      }
    );

    this.server.registerTool(
      "create_certificate_pdf",
      {
        description:
          "Generate and archive the certificate PDF for a fingerprint attested in this session with `attest_hash`. " +
          "The PDF is cryptographically signed, anchored in Bitcoin (OpenTimestamps) and archived server-side; " +
          "this tool returns the permanent links (the PDF itself is downloadable from its URL — it is never inlined here).",
        inputSchema: { sha256: sha256Param },
      },
      async ({ sha256 }) => {
        const hash = normalizeHash(sha256);
        if (!hash) return badHashError();
        const att = this.state.lastAttestation;
        if (!att || att.sha256 !== hash) {
          return toolError(
            "No attestation for this fingerprint in this session. Call `attest_hash` first (the certificate needs the signed attestation it returns)."
          );
        }
        let res;
        try {
          res = await apiFetch("/api/cert-pdf", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(att),
            // PDF generation + signing + anchoring can be slow: generous timeout.
            signal: AbortSignal.timeout(60_000),
          });
        } catch {
          return toolError("Could not reach the attestation service (network error or timeout) while generating the PDF.");
        }
        await drop(res);
        if (res.status === 429) {
          return toolError("The certificate endpoint is rate-limited right now. Wait a minute, then call this tool again.");
        }
        if (res.status === 400 || res.status === 403) {
          return toolError("The service refused the attestation token (tampered or inconsistent values). Re-run `attest_hash` and try again.");
        }
        if (res.status === 503) {
          return toolError("Certificate issuance is currently unavailable server-side (signing not configured). Check service_status.");
        }
        if (!res.ok) return upstreamError(res, "POST /api/cert-pdf");
        return text(
          [
            `Certificate generated and archived for ${hash}. Permanent links to give the user:`,
            "",
            certificateLinks(hash),
            "",
            "The Bitcoin anchoring proof starts as 'pending' and matures within a few hours.",
          ].join("\n")
        );
      }
    );
  }
}

export default {
  fetch(request, env, ctx) {
    activeApiBase = env?.IMGAUTH_BASE || DEFAULT_API_BASE;
    // Header pass-through (power users): a Bearer sg_k_…/sg_s_… on the /mcp
    // request is exposed to the agent as this.props.bearer. Malformed values
    // are dropped here so the credential never reaches imgauth (nor logs).
    const auth = request.headers.get("authorization") || "";
    const bearer = auth.replace(/^Bearer\s+/i, "").trim();
    ctx.props = { bearer: CREDENTIAL_RE.test(bearer) ? bearer : null };
    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "") {
      return new Response(
        [
          "attest-mcp-remote — remote MCP server for the Spazio Genesi attestation service.",
          "",
          "MCP endpoint (Streamable HTTP): /mcp",
          "Zero install: add the URL as a connector in your MCP client.",
          "No file ever transits: tools work on SHA-256 fingerprints computed locally.",
          "",
          "Service: https://attestazione.spaziogenesi.org",
          "Docs: https://imgauth.spaziogenesi.org/docs",
        ].join("\n"),
        { headers: { "content-type": "text/plain; charset=utf-8" } }
      );
    }
    if (url.pathname === "/mcp" || url.pathname.startsWith("/mcp/")) {
      return AttestMcpAgent.serve("/mcp", { binding: "MCP_OBJECT" }).fetch(request, env, ctx);
    }
    return new Response("Not found", { status: 404 });
  },
};
