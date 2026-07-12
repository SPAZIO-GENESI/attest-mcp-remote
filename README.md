# attest-mcp-remote

Remote MCP server (Streamable HTTP) for the [Spazio Genesi digital-work
attestation service](https://attestazione.spaziogenesi.org). **Zero install**:
add the URL as a connector in your MCP client and start verifying and
attesting.

**No file ever transits — by design.** MCP has no reliable client→server file
channel, and this service doesn't want one: every tool works on the SHA-256
fingerprint of the work. Agents with code execution compute it locally
(`sha256sum <file>`), so the file never leaves the machine it lives on — not
even through this server. For local-file tooling use the stdio package
[`@spazio-genesi/attest-mcp`](https://github.com/SPAZIO-GENESI/attest-mcp);
for humans, the [website](https://attestazione.spaziogenesi.org) (in-browser
hashing, full privacy) or the Telegram bot @SGAttestBot.

## Status

Work in progress (phase 2 of
[P26](https://github.com/SPAZIO-GENESI)): all 8 tools implemented and tested
locally (device flow validated end-to-end against an isolated imgauth
instance). Production deployment is the next phase.

## Tools

| Tool | Auth | What it does |
|---|---|---|
| `service_status` | none | Health of worker / archive / signer / Bitcoin anchor |
| `check_anchor` | none | OpenTimestamps proof lookup for a fingerprint |
| `verify_attestation` | none | Verify the server HMAC signature of an attestation |
| `lookup_certificate` | none | Archive lookup + permanent links for a fingerprint |
| `authorize` | starts device flow | User approves once in the browser (anti-bot check) |
| `complete_authorization` | device flow | Claims the 24h session token (kept in session state, never echoed) |
| `attest_hash` | session token or API key header | Bind a fingerprint to a signed server timestamp |
| `create_certificate_pdf` | session-scoped | Generate + archive the certificate PDF, returns permanent links |

Credentials: either the zero-config device flow above, or an
`Authorization: Bearer sg_k_…` header on the connection (e.g. Claude Code:
`claude mcp add --transport http attest <url> --header "Authorization: Bearer sg_k_…"`).
Self-service keys: https://imgauth.spaziogenesi.org/developer/keys

## Develop

```bash
npm install
npm run dev            # wrangler dev (default port 8787)
node test/smoke.mjs http://127.0.0.1:8787
```

`test/smoke.mjs` drives the Streamable HTTP transport end-to-end (initialize →
tools/list → tools/call) against real, public production data (read-only).
`test/smoke-auth.mjs` covers the credentialed flow and is a **local-only
harness**: it needs an isolated imgauth `wrangler dev` (own `--persist-to`
state, `SIGNER_URL` emptied) because the user-approval step is simulated by
writing the local D1 directly — see the header comment in the file.

## License

MIT — © Spazio Genesi ETS. This is a pure client of the public
[imgauth API](https://imgauth.spaziogenesi.org/docs); it defines no API
contract of its own.
