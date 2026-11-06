# S3 Express zonal endpoints — owner-run verification

Directory buckets (the S3 Express name shape `base--zone-id--x-s3`) are a
functional protocol in TeleDrive, not AWS One Zone infrastructure. This
page records the one part of the story that cannot be proven automatically
here: how a real S3 Express SDK behaves against a custom endpoint, and what
the owner must check on their own machine.

## Why this is owner-run

AWS SDKs decide whether to speak the zonal `s3express` dialect from the
**endpoint hostname**: botocore, for example, only selects its internal
`v4-s3express` signer when the endpoint looks like
`<bucket>.s3express-<zone>.<region>.amazonaws.com`. A self-hosted gateway
is addressed by an IP or a private DNS name, so the SDK never takes that
branch on its own.

That means:

- **The server side is proven.** Zonal requests signed with the
  `s3express` scope plus the signed `x-amz-s3session-token` header work —
  the test suite drives that flow with real botocore primitives
  (`S3ExpressIdentityResolver` and per-operation signer overrides) and
  proves expiry, revocation, mode enforcement and bucket crossover.
- **Full SDK auto-refresh against a custom endpoint is unverified**, and no
  claim is made that it works out of the box. An owner who points a stock
  S3 Express client at this deployment may see ordinary SigV4 (`s3`
  service) requests, which the zonal data plane refuses by design.

## What the owner should run

On a machine that has the real SDK (any language), against a disposable
deployment — never production data:

1. Configure the client for path-style addressing, region `us-east-1`,
   signature version `s3v4`, and the deployment's zonal-listener URL.
2. Create a directory bucket whose embedded zone equals
   `TELEDRIVE_S3_DIRECTORY_ZONE_ID` (default `use1-az1`). Note: TeleDrive
   currently accepts this CreateBucket only under the `s3` scope; an SDK
   that signs directory-bucket control calls with `s3express` gets
   `403 AccessDenied`. If that happens, create the bucket with the AWS CLI
   or a raw SigV4 `s3` request first, then continue with the session flow.
3. Call `CreateSession` with `SessionMode=ReadWrite`; confirm the response
   carries `Credentials` (access key, secret, session token) and an
   `Expiration` about five minutes out.
4. PUT, GET and LIST an object through the zonal plane and verify the
   bytes.
5. Repeat with `SessionMode=ReadOnly`: the PUT must fail closed.
6. Wait past the expiry (or delete the session's bucket) and confirm the
   next zonal call fails closed, then obtain a fresh session.

Record the SDK name and version, the endpoint form used, whether the
client sent `s3express` or `s3` in its Credential scope (the error body
names the required scope when it is wrong), and the exact responses.

## Honest outcomes

| Result | Meaning |
| --- | --- |
| Zonal flow works with the SDK's own auto-refresh | Record the SDK + version; it becomes a supported client row. |
| The SDK sends `s3` scope and the gateway refuses | Expected: the SDK needs a zonal-looking endpoint or an explicit signer override. Document the client as **untested for zonal auto-refresh**; the manual `s3express` flow above is the verified contract. |
| `CreateSession` itself fails | That is a server defect — capture the request and report it. |

The same rule as the rest of the project applies: an unverified client is
documented as unverified, never implied to work.
