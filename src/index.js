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

const API_BASE = "https://imgauth.spaziogenesi.org";
const SITE_BASE = "https://attestazione.spaziogenesi.org";
const FETCH_TIMEOUT_MS = 15_000;

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
  return fetch(API_BASE + path, {
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
    `- Certificate PDF: ${API_BASE}/api/cert?hash=${hash}`,
    `- OpenTimestamps proof (.ots): ${API_BASE}/api/ots?hash=${hash}`,
    `- Verify with the file in the browser: ${SITE_BASE}?hash=${hash}`,
  ].join("\n");
}

export class AttestMcpAgent extends McpAgent {
  server = new McpServer({
    name: "spazio-genesi-attestation",
    version: "1.0.0",
  });

  // Session state (Durable Object). The device-flow session token will live
  // here in a later phase; kept empty for now.
  initialState = {};

  async init() {
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
              `- Download the proof: ${API_BASE}/api/ots?hash=${hash}`,
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
  }
}

export default {
  fetch(request, env, ctx) {
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
