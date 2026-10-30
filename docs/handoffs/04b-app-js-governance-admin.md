# 04b — app.js: governance and the admin console leave app.js

Commits:

- `dc54233 refactor(web): extract the S3 governance group into governance.js`
- `5998590 refactor(web): extract the admin console group into admin.js`

Move-only splits. No method body, getter, endpoint, state initializer or
confirmation string was changed. The non-move edits are:

- the two guarded spreads and their comments in `app.js`,
- one `<script src>` on `s3-governance.html` and six on the admin pages,
- a comment block above `fmtRel`/`keyExpired` explaining why they stay,
- re-indenting the moved blocks by two spaces so they sit inside the
  fragment factories (the same normalisation `buckets.js` and `telegram.js`
  use).

`LOG_NOISE_RE` moved into `admin.js`'s IIFE because `loadLogs` /
`_ingestLogEntries` are its only readers. It is now a `const` local to that
file instead of a page-global `const`; nothing outside `admin.js` referenced
it.

## 1. `web/static/governance.js` (new, 387 lines)

Exports `governanceState()` / `governanceMethods()`.

State: `govBucket`, `govTab`, `govLoaded`, `govBusy`, `govError`,
`govNotice`, `govCredentials`, `govCredentialId`, `govPolicy`,
`govOwnership`, `govPab`, `govLock`, `govWebsite`, `govNotify`,
`govReplication`, `govTiering`, `govReports`, `govReportForm`, `govTabs`.

Methods: `govInit`, `govUrl`, `govCredentialBody`, `govCall`, `govFail`,
`govSelectBucket`, `govGo`, `govLoad`, `govMutate`, and every
`load*/save*/delete*/enable*/add*/remove*Gov*` handler for policy, ownership,
public-access block, object lock, website, notifications, replication,
Intelligent-Tiering and storage reports (37 methods total).

One correction to the assignment text: the loader is `loadGovPolicy` /
`saveGovPolicy`, not `govLoadPolicy`. No renames were made.

## 2. `web/static/admin.js` (new, 370 lines)

Exports `adminState()` / `adminMethods()`.

State: dashboard/queue/history (`dashboard`, `dashAccounts`, `usageSeries`,
`gc`, `gcScope`, `gcPreview`, `queueRows`, `historyRows`, `bucketUsage`,
`versionRows`, `versionBucket`), API keys (`apiKeys`, `newKeyName`,
`newKeyExpiry`, `newKeyExpiryPreset`, `createOpen`, `permSearch`, `catOpen`,
`keyScopesList`, `endpointPermissions`, `endpointGroups`,
`groupDescriptions`, `legacyScopes`, `endpointCategories`, `selectedScopes`,
`createdKey`), logs (`logEntries`, `logLive`, `_logTimer`, `logFilter`,
`logLimit`, `logHideNoise`, `logHiddenCount`), users (`users`,
`showNewUser`, `newUser`).

Methods: `refreshGC`, `toggleGC`, `collectGC`, `refreshDashboard`,
`refreshHistory`, `refreshVersions`, `usagePct`, `runJob`, `loadPermissionCatalog`,
`toggleAllEndpoints`, `toggleEndpointCategory`, `categoryFullySelected`,
`endpointsIn`, `countSelected`, `toggleCatOpen`, `categoryMatches`,
`permMatches`, `refreshKeys`, `createKey`, `rotateKey`, `revokeKey`,
`loadLogs`, `toggleLogLive`, `_startLogStream`, `_stopLogStream`,
`_ingestLogEntries`, `loadUsers`, `createUser`, `deleteUser`,
`changePassword`, `changeRole`.

### Deliberately left in app.js

- `fmtRel` and `keyExpired`: `api-management.html` calls both and would be
  happy without them in app.js, but `credentials.html` calls `keyExpired`
  (`web/static/credentials.html:397`) and does **not** load `admin.js`.
  Moving them would have forced `admin.js` onto the credentials page for one
  predicate. They are small and shared, so they stay in `app.js`.
- `fmtBytes`, `quotaPct`, `fmtTs`, `copyText`, `toast`, `api`,
  `confirmDelete`, `isAdmin`/`canWrite`, `navActive`, `login`/`logout`,
  `init`, and the auth state. All are used by three or more pages or by
  fragments that must not depend on `admin.js`.
- `mustChangePassword`: written by `init()` in app.js and read by
  `users.html`. It is auth/session state, not user-admin state.

## Cross-file call edges (the thing the composition test cannot see)

Found by scanning `this.<name>(` in every fragment and subtracting the names
each fragment defines:

```
buckets.js     -> api, confirmDelete, refreshTgSessionStatus, toast
credentials.js -> api, toast
telegram.js    -> api, confirmDelete, toast
governance.js  -> refreshBuckets, toast
admin.js       -> api, confirmDelete, refreshBuckets, toast
```

The two new fragments therefore depend on:

| Edge | Direction | Consequence |
|---|---|---|
| `governance.js` → `this.refreshBuckets()` and `this.buckets` | governance.js calls **buckets.js** | `s3-governance.html` must keep loading `buckets.js` before `governance.js`/`app.js` (it already did). It also reads `this.buckets[0].name` in `govInit`. |
| `governance.js` → `this.isAdmin` getter | governance.js → **app.js** | `govMutate` gates writes. The getter stays in app.js, so no extra tag. |
| `admin.js` → `this.refreshBuckets()` | admin.js calls **buckets.js** | Only reachable through `refreshHistory()` → and only `history.html` calls it (markup `refreshVersions` and `init()`'s `/history` branch). `history.html` already loads `buckets.js`. `admin.js` is safe on the other five pages because they never reach that line. |
| `admin.js` → `api` / `toast` / `confirmDelete` | admin.js → **app.js** | Resolved on the merged Alpine object; load order fragment-before-app.js is required. |

### The invisible dependency, measured

`queue.html` has **no** method call in its markup at all — it only binds
`queueRows`, `currentUser`, `currentRole`. The test therefore says nothing
about `admin.js` on that page. But `init()` has
`path === '/queue' → await this.refreshDashboard(); await this.refreshGC();`.
Proof the test misses it: with `admin.js` removed from `queue.html`,
`tests/web/test_page_composition.py` still reports `2 passed`, while the page
would throw `this.refreshDashboard is not a function` on load. That is why
`queue.html` got a tag the test never asked for.

Same class of hidden edge, checked and **not** present: no page outside the
six reaches `loadUsers`, `loadLogs`, `refreshKeys`, `loadPermissionCatalog`,
`refreshHistory`, `refreshDashboard`, `refreshGC` or `govInit` from
`init()`. The only other `init()` branches are `/settings/general`,
`/settings/telegram`, `/s3/buckets`, `/s3/credentials` and `/s3/governance`,
all covered by their own fragments.

## Script tags: page, tag, evidence

### governance.js — one page

| Page | Evidence |
|---|---|
| `web/static/s3-governance.html` | Markup calls `govGo`, `govSelectBucket`, `govReportNew`, `govReportEdit`, `govTieringNew`, `govTieringEdit`, `addGovReplicationRule`, `addGovTierRow`, `deleteGovPolicy`, `deleteGovReplication`, `deleteGovReport`, `deleteGovTiering`, `deleteGovWebsite`, `enableGovLock`, `saveGov*`; binds every `gov*` state field. `init()` at `/s3/governance` calls `govInit()`, which calls `refreshBuckets()` (buckets.js, already loaded). |

Load order now: `buckets.js`, `governance.js`, `app.js`.

### admin.js — six pages

| Page | Evidence |
|---|---|
| `web/static/index.html` (`/`, `/dashboard`) | Markup calls `runJob`, `refreshDashboard`, `toggleGC`, `collectGC`; binds `dashboard`, `dashAccounts`, `usageSeries`, `gc`, `gcScope`, `gcPreview`, `bucketUsage`. `init()` calls `refreshDashboard` + `refreshGC` and sets a 30 s interval on `refreshDashboard`. |
| `web/static/queue.html` (`/queue`) | **Markup calls none.** `init()` calls `refreshDashboard` + `refreshGC`; markup binds `queueRows`. Invisible to the test — see above. |
| `web/static/history.html` (`/history`) | Markup calls `refreshVersions`; binds `historyRows`, `versionRows`, `versionBucket`. `init()` calls `refreshHistory`, which calls `refreshBuckets` (buckets.js already loaded) and `refreshVersions`. |
| `web/static/users.html` (`/users`) | Markup calls `createUser`, `deleteUser`, `changePassword`, `changeRole`; binds `users`, `showNewUser`, `newUser`. `init()` calls `loadUsers`. |
| `web/static/logs.html` (`/logs`) | Markup calls `loadLogs`, `toggleLogLive`; binds every `log*` field. `init()` calls `loadLogs`. |
| `web/static/api-management.html` (`/api-management`) | Markup calls `createKey`, `refreshKeys`, `copyText`, `toggleEndpointCategory`, `toggleCatOpen`, `categoryMatches`, `categoryFullySelected`, `countSelected`, `endpointsIn`, `permMatches`; binds `apiKeys`, `selectedScopes`, `endpointCategories`, `legacyScopes`, `groupDescriptions`, `catOpen`, `permSearch`, `createdKey`, `createOpen`, `newKey*`. `init()` calls `refreshKeys` and `loadPermissionCatalog`. |

Load order on all six: `admin.js`, `app.js` (`history.html` also keeps
`buckets.js` first).

Pages that deliberately did **not** get `admin.js`: `login.html`,
`settings.html`, `telegram.html`, `buckets.html`, `credentials.html`,
`s3-governance.html`. Their markup, their `init()` branch and their fragments
touch no admin method or state.

## The safety net

`tests/web/test_page_composition.py` needed no change: `is_group_file()`
detects any file containing `global.<name>State|Methods =`, so both new
fragments are recognised as optional groups automatically.

Before adding the tags it reported (abridged, both fragments removed):

```
index.html: calls collectGC() but no loaded script defines it
index.html: calls refreshDashboard() but no loaded script defines it
index.html: calls runJob() but no loaded script defines it
index.html: calls toggleGC() but no loaded script defines it
s3-governance.html: calls addGovReplicationRule() but no loaded script defines it
... (govSelectBucket, govGo, govReportEdit, enableGovLock, saveGov*, ...)
```

With the tags in place it passes. `queue.html` is the proof of the gap
described above.

## Final line counts

| File | Lines |
|---|---|
| `web/static/app.js` | 167 (was 861) |
| `web/static/admin.js` | 370 (new) |
| `web/static/governance.js` | 387 (new) |
| `web/static/telegram.js` | 288 (unchanged) |
| `web/static/buckets.js` | 375 (unchanged) |
| `web/static/credentials.js` | 767 (unchanged) |

`app.js` is now a 167-line shell: five guarded spreads, auth/session state,
`init()`, `navActive`, the role getters, `api`/`toast`/`confirmDelete`, the
formatters (`fmtTs`, `fmtBytes`, `fmtRel`, `quotaPct`, `keyExpired`),
`copyText`, and `login`/`logout`.

## Stop splitting app.js

There is nothing cohesive left. What remains is:

- **the bootstrap itself** (`init`, clear/spread order, auth state) — cannot
  move without changing how every page starts;
- **shared primitives** used by 3+ fragments on 3+ pages (`api`, `toast`,
  `confirmDelete`, `fmtTs`, `fmtBytes`, `fmtRel`, `quotaPct`, `keyExpired`,
  `copyText`, `navActive`, the role getters).

Extracting the primitives would mean every page loads a `core.js` *and* its
fragment *and* app.js, i.e. more tags and more ordering hazards for ~90
lines, and the guarded-spread pattern would gain a load-order dependency that
is harder to audit than the current one-file core. The 861 → 167 result is
the natural end state. If app.js grows again, grow it here rather than
starting a sixth fragment.

## Verification (exact commands and results)

The main working tree is unusable for the Python suite right now: another
agent's in-progress `web/app.py` / `web/routers/` refactor raises
`NameError: name 'telegram_router' is not defined` at import, which errors
80 collection items in `tests/web`. That is not from this change (this change
touches only `web/static/**` and this document). To verify against a clean
tree I used a throwaway worktree at my governance commit with only my static
files copied in:

```
$ git worktree add /tmp/opencode/verify dc54233
$ cp web/static/{app,admin,governance}.js web/static/{index,queue,history,users,logs,api-management}.html /tmp/opencode/verify/web/static/

$ node --check web/static/app.js && node --check web/static/governance.js && node --check web/static/admin.js
NODE_OK

$ /home/babico/Projects/TeleDrive/.venv/bin/python -m pytest tests/web -q -n 4
249 passed, 5 warnings in 43.74s

$ /home/babico/Projects/TeleDrive/.venv/bin/python -m pytest tests/meta -q -n 4
150 passed in 8.39s
```

`tests/meta` is green, unlike handoff 04a's run; the route-surface failure it
saw belonged to the routing refactor and is resolved at this commit.

No Python file changed, so `bandit` / `compileall` are unaffected; the
repository-level commands still to run before merge, per
`docs/handoffs/README.md`, are `pytest tests/s3 tests/web tests/storage
tests/meta -q -n 4`, `bandit -q -r teledrive web -ll` and
`python -m compileall -q teledrive web` — run them once the concurrent
`web/app.py` refactor lands.

## Working tree note

`web/app.py`, `web/routers/` and the untracked router files belong to the
concurrent routing refactor and are **not** part of `dc54233` or `5998590`.
Only `web/static/**` (JS, HTML) was staged, then this document.
