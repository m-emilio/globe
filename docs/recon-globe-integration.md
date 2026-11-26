# Recon globe integration — review checklist

This branch adds an admin-only React overlay to the existing Cobe globe stage. It uses the v276 POST /admin/purple-team/recon form contract (action=export), with the existing HttpOnly session cookie. Node positions are logical, not geographic. Results stay in component memory and are cleared on close or loss of admin state.

## Important deployment gate

Cloudflare's deployment metadata identified v276 as active, but its generic script download returned a base bundle without the v276 handler. The main repository also lacked that handler when inspected. Do not deploy this branch as a replacement Worker until the version-specific production source and prior server extensions are reconciled. No auth bypass or production secret is included here.

## Verification

- Run npm ci, node scripts/recon-graph-selftest.mjs, npm run check, and npm run build:client:sri in a controlled checkout.
- Verify a signed-out request to the recon POST returns 401 or 403 and never returns data.
- Verify a signed-in non-admin is denied.
- Sign in with the normal allowlisted administrator device key, open Infrastructure recon on the globe, submit a known authorized public test domain, and verify graph nodes and source evidence.
- Verify node selection, close/reset, logout, expired sessions, rate limiting, and failure handling.
- Verify the existing globe controls, PGP/PQC authentication, payments, and visitor WebSocket feed remain functional.
- Never copy the device private key or session cookie into a test script or GitHub.

The fixture test is not an authenticated browser end-to-end test. Keep the existing live version until the source mismatch is resolved.
