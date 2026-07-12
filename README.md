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

Work in progress (phase 1 of
[P26](https://github.com/SPAZIO-GENESI)): public tools implemented and tested
locally. Device-flow authorization and hash attestation arrive in the next
phase; production deployment after that.

## Tools

| Tool | Auth | What it does |
|---|---|---|
| `service_status` | none | Health of worker / archive / signer / Bitcoin anchor |
| `check_anchor` | none | OpenTimestamps proof lookup for a fingerprint |
| `verify_attestation` | none | Verify the server HMAC signature of an attestation |
| `lookup_certificate` | none | Archive lookup + permanent links for a fingerprint |

## Develop

```bash
npm install
npm run dev            # wrangler dev (default port 8787)
node test/smoke.mjs http://127.0.0.1:8787
```

The smoke test drives the Streamable HTTP transport end-to-end (initialize →
tools/list → tools/call) against real, public production data.

## License

MIT — © Spazio Genesi ETS. This is a pure client of the public
[imgauth API](https://imgauth.spaziogenesi.org/docs); it defines no API
contract of its own.
