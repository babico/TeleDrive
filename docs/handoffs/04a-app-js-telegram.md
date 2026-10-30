# 04a — app.js: the Telegram/settings group moves to telegram.js

Commit: `bda11a1 refactor(web): extract the Telegram/settings group into telegram.js`

Move-only split. No method body, getter, endpoint, state initializer or
confirmation string was changed. The non-move edits are the guarded spread
and its comment in `app.js`, plus one script tag on three pages. The moved
blocks were re-indented by two spaces to sit inside the fragment's factory
(the same normalisation `buckets.js` uses); nothing else in their text
changed.

## What moved

`web/static/telegram.js` (new, 288 lines) exports `telegramState()` and
`telegramMethods()`, copying the `buckets.js` shape:

```js
global.telegramState = function () { return { ... }; };
global.telegramMethods = function () { return { ... }; };
```

`app.js` spreads them only when the file is present:

```js
...(typeof telegramState === 'function' ? telegramState() : {}),
...(typeof telegramMethods === 'function' ? telegramMethods() : {}),
```

### Methods (verbatim)

`loadSettings`, `saveSettings`, `refreshChannels`, `addChannel`,
`activateChannel`, `deleteChannel`, `refreshTgSessionStatus`,
`saveStrategy`, `loadReplication`, `saveReplication`, `repairReplication`,
`editAccountQuota`, `saveAccountQuota`, `checkTgSession`, `deleteTgSession`,
`refreshFlood`, `sendTgCode`, `verifyTgCode`.

Also moved, although not enumerated in the assignment: the three flood
getters `floodCountdown`, `floodExpiresLocal`, `floodLastText`. They read
only `floodExpiresAt` / `floodNow` / `floodLast`, all of which moved with
the state, and only `telegram.html` consumes them. Leaving them in `app.js`
would have split one feature across two files. Bodies unchanged.

### State moved

`config`, `activeChannelId`, `activeChannelLabel`, `channels`,
`showAddChannel`, `newChannelName`, `newChannelId`, `newChannelStrategy`,
`newChannelScratch`, `tgApiId`, `tgApiHash`, `tgPhone`, `tgSessionStatus`,
`tgSessions`, `tgChecking`, `strategySel`, `replicaSel`, `replication`,
`tgSessionError`, `floodActive`, `floodLast`, `floodScope`,
`floodExpiresAt`, `floodNow`, `tgCodeVisible`, `tgCode`, `tgPassword`,
`tgSessionToken`, `extensionsStr`, `quotaEditAccount`, `quotaEditBytes`.

`quotaEditAccount` / `quotaEditBytes` were defined between
`repairReplication` and `editAccountQuota` in `app.js`; they stay in that
position inside `telegramMethods()`, the way `presignKey` stayed inside
`bucketMethods()`.

Deliberately **not** moved because they are shared by every page or by
another group: `api`, `toast`, `confirmDelete`, `fmtTs`, `fmtBytes`,
`copyText`, `isAdmin` / `canWrite`, and `init()` (which only *calls*
`loadSettings`/`refreshFlood` on the two settings routes and writes
`floodNow` from a timer). `dashboard.strategy` is a different field from
`strategySel`. `gc*` stays with the dashboard/GC group.

## Script tags added (and the evidence for each page)

All three got `<script src="/static/telegram.js"></script>` **immediately
before** `/static/app.js`.

| Page | Evidence |
|---|---|
| `web/static/settings.html` | Markup binds `config.upload.*`, `config.state.*`, `config.app.*`, `config.storage.*`, `extensionsStr` and calls `saveSettings()`. `init()` at `/settings/general` calls `loadSettings()`, which calls `refreshChannels()`, `refreshTgSessionStatus()` and `loadReplication()`. |
| `web/static/telegram.html` | Markup calls `addChannel`, `activateChannel`, `deleteChannel`, `sendTgCode`, `verifyTgCode`, `saveStrategy`, `saveReplication`, `repairReplication`, `editAccountQuota`, `saveAccountQuota`, `checkTgSession`, `deleteTgSession`, and binds every channel/session/flood field, including the `floodCountdown`/`floodExpiresLocal`/`floodLastText` getters. `init()` at `/settings/telegram` calls `loadSettings()` and `refreshFlood()`. |
| `web/static/buckets.html` | No telegram method appears in its markup, but buckets.js `editPin()` calls `this.refreshTgSessionStatus()` (`web/static/buckets.js:110`), and the Pin button calls `editPin()` (`buckets.html:160`). Without the fragment that button throws at runtime. |

Every other page's markup and `init()` branch touches none of the moved
methods or state. `history.html` / `s3-governance.html` load `buckets.js`
only for `refreshBuckets`; neither reaches `editPin`.

## The safety net, and what it did not catch

`tests/web/test_page_composition.py` passes with the tags in place. Before
adding them it reported:

- `settings.html: calls saveSettings() but no loaded script defines it`
- `telegram.html`: the twelve called methods listed above.

Two real dependencies were invisible to it, and were found by reading the
code:

1. **`buckets.html` never failed.** The test only parses HTML Alpine
   attributes; it does not follow calls between JS files. `buckets.html`
   calls `editPin()` (loaded from `buckets.js`), and `editPin()` calls
   `refreshTgSessionStatus()`. So the test would have stayed green while the
   Pin button broke.
2. **`settings.html` failed only on `saveSettings()`.** Its `loadSettings()`
   dependency exists solely in `init()`'s `/settings/general` branch, which
   the test does not parse.

No page calls a moved method that nothing defines. The test exposed no
pre-existing undefined method; its only failures were the two real missing
fragments above plus the `settings.html` `saveSettings` call.

## New line counts

| File | Lines |
|---|---|
| `web/static/app.js` | 861 (was 1 121) |
| `web/static/telegram.js` | 288 (new) |
| `web/static/buckets.js` | 375 (unchanged) |
| `web/static/credentials.js` | 767 (unchanged) |

## Verification (exact output)

```
$ node --check web/static/app.js && node --check web/static/telegram.js
node --check: OK

$ .venv/bin/python -m pytest tests/web/test_page_composition.py tests/web/test_credentials_ui.py -q
29 passed in 1.95s

$ .venv/bin/python -m pytest tests/web -q -n 4
249 passed, 5 warnings in 45.11s (0:00:45)

$ .venv/bin/python -m pytest tests/meta -q -n 4
1 failed, 149 passed in 9.17s
# FAILED tests/meta/test_route_surface.py::test_the_authorization_surface_is_unchanged
# "routes disappeared from the surface": GET /, /login, /settings/*, /s3/*,
# /share/{token}, /site/*, /storage, /{page_name} ...
```

That failure is **not from this change**: at the time of writing another
agent is rewriting `web/app.py` and moving routes into `web/routers/`, and
that test scans only `web/app.py`. This commit touches no Python file. The
previous handoff's expected `test_ci_workflows` failure is gone — the
composition test is now registered.

I also re-ran the composition test with the three new tags temporarily
removed: it failed with exactly the list above, then passed again after
restoration.

## What the next agent should extract

**Best next unit: the S3 governance fragment** (unchanged recommendation
from 04). `app.js:524-861`, ~338 lines, one consumer
(`s3-governance.html`), and it depends only on `refreshBuckets` (already
guaranteed by `buckets.js` loading first) plus `api`/`toast`/`isAdmin`.
Load order on that page: `buckets.js`, `governance.js`, `app.js`.

After that, the remaining groups are small and page-local — users (~28
lines), API keys (~55 plus the permission-catalogue helpers around
`loadPermissionCatalog`), logs (~64 including the stream), dashboard/GC/
history (~300 but three routes share `refreshDashboard`/`refreshHistory`
and `queue.html` is one of them) — so none is worth a separate fragment
until governance is gone.

**Do not split `settings.html` from `telegram.html` further.** They share
`config`, `channels`, `tgSessions`, `flood*` and both call `loadSettings()`
in `init()`; this handoff deliberately keeps them as one fragment loaded
on both pages, as 04 warned.

## Working tree note

`web/app.py`, `web/deps.py`, `web/errors.py` and the new `web/routers/`
directory belong to the concurrent routing refactor and are **not** part of
`bda11a1`. Only `app.js`, `telegram.js` and the three HTML files were
staged.
