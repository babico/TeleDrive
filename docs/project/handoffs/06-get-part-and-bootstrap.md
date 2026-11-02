# Handoff 06 — GetObject partNumber and first-boot admin security

**State:** Ready for implementation; no code changes claimed. **Read first:** [execution plan](../plans/2026-11-02-s3-fidelity.md), \`docs/project/handoffs/README.md\`, \`docs/reference/s3-specs.md\`.

## Task A — GET ?partNumber=N

Current blocking code: \`web/s3_gateway/dispatch.py\` rejects \`partNumber\` outside UploadPart; \`web/s3_gateway/objects.py::_handle_object_read\` streams whole/ranged objects. Source-of-truth logical MPU layout is \`MultipartStore.object_parts_for_version(item.id, item.size)\` in \`teledrive/s3/multipart.py\`; it verifies count, total length, ordering, SHA256, multipart ETag and copied/legacy snapshots.

1. Change routing ONLY for signed object GET \`partNumber\` (not HEAD, PUT, DELETE, or object-attributes). Extend allowlists and operation/query guards without introducing an authorization fallthrough.
2. Parse exactly one decimal \`partNumber\` from 1 through 10,000; reject duplicates, negative, zero, malformed, overflow, unsupported simultaneous Range and unsupported selectors with consistent AWS-modeled errors; verify SigV4 includes query. Verify AWS actual behavior for single-PUT \`partNumber=1\` and nonexisting parts before deciding whether to support or reject them.
3. Request immutable \`object_parts_for_version\`; fail closed for corrupt/absent required layout, never reconstruct synthetic logical parts from Telegram chunk sizes. Sum prior part sizes in stored completion order (not part-number arithmetic; uploads may be sparse). Map inclusive HTTP range \`[start, end)\` for requested part.
4. Reuse existing \`TelegramObjectStorage.iter_bytes(..., start, end, sse_key)\`, archive-read gate, versionId permissions, SSE-C/envelope validation, preconditions, access accounting, conditional response overrides and streaming close hooks. Do not bypass \`_handle_object_read\`.
5. Derive \`Content-Length\`, \`Content-Range\`, \`x-amz-mp-parts-count\` where modeled, 200/206 response choice and checksum suppression by a real botocore + AWS wire contract, not guesswork. Zero-byte final part, single-part MPU and legacy journal handling must be explicit. \`HEAD ?partNumber\` must be independently specified before enabling.
6. Tests: actual boto3 \`get_object(PartNumber=N)\` against uvicorn, first/middle/last part, sparse numbered completion, versioned old object, CopyObject of completed MPU, wrong-owner credential, corrupt snapshot, no Telegram read on invalid input, Range+partNumber, SSE modes, archived object, interrupted stream/retry and restart. Assert exact bytes and no catalog mutation.
7. Update S3 spec's old 501 wording only after green CI. Mark feature implemented; never alter 114/0/2 operation count for a variant.

**Common hazard:** Telegram chunk boundaries are **not** S3 multipart logical boundaries. Hash each returned byte slice and verify the original MPU part digest; don't transform the request into a storage-chunk index.

## Task B — enforce bootstrap password change server-side

Current behavior: \`web/routers/auth.py::_default_admin_password_in_use\` and \`GET /auth/me\` only advise the UI. The original \`admin/admin\` remains a deliberate bootstrap, not a reusable production credential.

1. Implement a central gate after session identity resolution, before route handler, S3 authorization and WebSocket subscription. Gate must be based on account state (seeded admin password still equals shipped default), not a trustable browser flag.
2. Allow exactly login, current-user info, logout, a **self-password-change** endpoint, health/certificate/static needed to complete the flow. Restrict password change to the authenticated same account, validate current password, require strong new password different from \`admin\`, CSRF and same-origin protections; enforce secure session rotation/revocation.
3. Deny all other authenticated operations including S3 credential issue/presign, API key minting, user-management writes, WebSocket admin logs and REST data. Document whether any existing API key issued while default password was active must be revoked or denied until rotation.
4. Cover first boot, existing custom admin password, concurrent requests, session cookie vs bearer, revoked/expired sessions, proxy headers, name collisions and no bootstrap deadlock. Keep existing admin row untouched on restart.
5. Tests go to \`tests/web/test_bootstrap_password_gate.py\`; ensure \`tests/meta/test_route_surface.py\` remains consistent if adding a new self-service route; update GUI flow and \`docs/start/first-upload.md\`.

**Evidence to record:** unit/HTTP tests, negative API/S3/WebSocket tests, fresh-container smoke on real config, exact commit SHA + CI links. Stop and hand off rather than shipping a partial gate.
