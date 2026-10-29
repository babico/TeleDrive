# 04 — app.js: the S3 bucket browser moves to buckets.js

Commit: `6a364c4 refactor(web): extract the S3 bucket browser into buckets.js`

Move-only split. No method body, endpoint, or confirmation string was
changed. The one non-move edit in `app.js` is the guarded spread plus its
comment.

## What moved

`web/static/buckets.js` (new, 375 lines) exports `bucketState()` and
`bucketMethods()`, copying the `credentials.js` pattern:

```js
global.bucketState = function () { return { ... }; };
global.bucketMethods = function () { return { ... }; };
```

`app.js` now spreads them only when the file is present:

```js
...(typeof bucketState === 'function' ? bucketState() : {}),
...(typeof bucketMethods === 'function' ? bucketMethods() : {}),
```

### Methods (verbatim)

`presignObject`, `shareObject`, `createShare`, `refreshShares`,
`revokeShare`, `editPin`, `savePin`, `editCors`, `saveCors`,
`downloadObject` (**both historical definitions**), `contentUrl`,
`previewUrl`, `previewKindFor`, `previewObject`, `searchObjects`,
`reindexContents`, `syncSelectedKeys`, `deleteSelected`, `renameObject`,
`moveObject`, `handleDrop`, `handleFileInput`, `encKeys`,
`rememberEncKey`, `isEncKey`, `uploadFiles`, `saveBlob`, `refreshBuckets`,
`createBucket`, `deleteBucket`, `browseBucket`, `deleteObject`,
`editQuota`, `saveQuota`.

The requested names `selectBucket`, `pageNext`, `pagePrev` and the state
field `objects` do not exist in `app.js` at this commit (the page has no
pagination and the list is `bucketObjects`). Nothing was invented for them.

### State moved

`searchQuery`, `searchResults`, `dropHover`, `uploading`, `uploadName`,
`uploadPct`, `selectedKeyList`, `selectedKeys` (`Set`), `previewOpen`,
`previewBucket`, `previewKey`, `previewKind`, `previewSize`, `previewText`,
`searchMode`, `corsRules`, `buckets`, `currentBucket`, `bucketObjects`,
`showNewBucket`, `newBucketName`, `quotaEditBucket`, `quotaMaxSize`,
`quotaMaxObjects`, `presignKey`, `presignBucket`, `presignExpiry`,
`presignedUrl`, `corsBucket`, `pinBucket`, `pinAccount`, `shareKey`,
`shareBucket`, `shareExpiry`, `shareMaxDownloads`, `sharePassword`,
`shareUrl`, `shares`, `shareOrigin`, `encEnabled`, `encPass`.

Deliberately **not** moved because they are shared with other pages:
`copyText` (api-management + buckets), `fmtBytes` / `fmtTs` / `toast` /
`api` / `confirmDelete` (every page), `isEncKey`'s sibling
`uploadFiles` was moved because only the bucket page uploads, and
`bucketUsage` (dashboard) which is a different field from `buckets`.

## Landmine preserved, not fixed

`app.js` defined `downloadObject` twice: a `window.open` version and later
an async `fetch` + client-side-decrypt version. The later definition
shadowed the first. Both were moved in the same order, so the effective
implementation is unchanged. A future agent may delete the dead first
definition, but that is a separate commit with a test.

## Script tags added (and the evidence for each page)

All three got `<script src="/static/buckets.js"></script>` **immediately
before** `/static/app.js`.

| Page | Evidence |
|---|---|
| `web/static/buckets.html` | Its own markup calls 26 bucket methods: `refreshBuckets`, `searchObjects`, `reindexContents`, `downloadObject`, `previewObject`, `createBucket`, `createShare`, `deleteBucket`, `browseBucket`, `deleteSelected`, `syncSelectedKeys`, `presignObject`, `shareObject`, `renameObject`, `moveObject`, `deleteObject`, `editCors`, `editPin`, `savePin`, `saveCors`, `editQuota`, `saveQuota`, `revokeShare`, `handleDrop`, `handleFileInput`, `isEncKey` (via `@click`/`@change`/`x-model`). |
| `web/static/history.html` | No bucket method is named in its markup, but `init()` at `path === '/history'` calls `refreshHistory()`, which ends with `await this.refreshBuckets()` (`app.js:266` → `app.js:356`). Without the fragment that path throws at runtime. |
| `web/static/s3-governance.html` | No bucket method is named in its markup, but `init()` at `path === '/s3/governance'` calls `govInit()`, which starts with `await this.refreshBuckets()` and then reads `this.buckets` (`app.js:257` → `app.js:785-794`). |

Every other page loads neither fragment and its `init()` branch never
touches bucket state.

## New line counts

| File | Lines |
|---|---|
| `web/static/app.js` | 1 121 (was 1 469) |
| `web/static/buckets.js` | 375 (new) |
| `web/static/credentials.js` | 767 (unchanged) |

## The safety net

`tests/web/test_page_composition.py` (new) feeds every page through the
same shape check:

1. script `src` list in document order;
2. Alpine attributes `@*`, `x-text`, `x-show`, `x-model`, `x-html`,
   `x-init`; quoted strings are stripped first so prose like
   `'Search results ('` is not mistaken for a call;
3. bare calls only (`name(`) so `this.toast(` and `corsRules.splice(` are
   not component calls;
4. definitions parsed as `name(...){`, `name: function(...)`,
   `name: async(...)` from `app.js` and every loaded non-vendor script;
5. assert every called name is defined by a loaded script, and if an
   optional fragment (`credentials.js`, `buckets.js`, or any
   `global.*State`/`global.*Methods` exporter) defines it, that fragment
   loads **before** `app.js`.

Before the tags were added it failed with every real bucket method called
by `buckets.html` reported undefined; after, both tests pass. It did **not** expose any undefined
method that was already broken: the initial failures were all bucket-group
methods plus string-prose false positives in the test itself.

`tests/meta/test_ci_workflows.py::test_every_test_file_is_referenced_by_a_real_ci_workflow`
now fails because this new test file is not yet in a workflow. Per the
assignment the workflow file is owned by another agent; the parent session
said it would register the test. Do not edit `.github/` from this handoff.

## What the next agent should extract

**Best next unit: the S3 governance fragment** (`s3-governance.html` only).
Move `govBucket` … `govTabs` state plus `govInit`, `govUrl`,
`govCredentialBody`, `govCall`, `govFail`, `govSelectBucket`, `govGo`,
`govLoad`, `govMutate`, `loadGov*`, `saveGov*`, `deleteGov*`,
`enableGovLock`, `addGovReplicationRule`, `removeGovReplicationRule`,
`govTieringNew`, `govTieringEdit`, `addGovTierRow`, `removeGovTierRow`,
`govReportNew`, `govReportEdit`. It is ~360 lines, has no other page
consumer, and only depends on `refreshBuckets` (now guaranteed by loading
`buckets.js` before it) and the shared `api`/`toast`/`isAdmin` members.
Load order on that page: `buckets.js`, `governance.js`, `app.js`.

**Do NOT split `settings.html` from `telegram.html` as separate
per-page fragments.** They share `config`, `activeChannel*`, `channels`,
`tgSessions`, `flood*` and, crucially, `init()` calls `loadSettings()` on
both `/settings/general` and `/settings/telegram`; `loadSettings()` itself
calls `refreshChannels()`, `refreshTgSessionStatus()` and
`loadReplication()`. A naive split needs both fragments on both pages
(three tags total on one page is the stop signal). Either extract the
whole settings/telegram cluster as one file loaded on both pages, or leave
it in `app.js`.

Also avoid splitting `dashboard` from `queue`: `queue.html` reuses
`refreshDashboard()` and its state, so they are one component even though
they are two routes.

## Verification (exact output)

```
$ node --check web/static/app.js && node --check web/static/buckets.js && echo "node --check ...: OK"
node --check web/static/app.js && node --check web/static/buckets.js: OK

$ .venv/bin/python -m pytest tests/web -q -n 4
249 passed, 5 warnings in 69.74s (0:01:09)

$ .venv/bin/python -m pytest tests/meta -q -n 4
...
FAILED tests/meta/test_ci_workflows.py::test_every_test_file_is_referenced_by_a_real_ci_workflow
1 failed, 146 passed in 27.58s
# expected: tests/web/test_page_composition.py is not registered in .github/workflows
# yet (owned by another agent). Nothing else in tests/meta fails.
```

`tests/web/test_credentials_ui.py` passes unchanged: it still finds
`credentialState()` / `credentialMethods()` and both
`typeof ... === 'function'` guards in `app.js`.

## Note on the working tree

`web/app.py`, `web/deps.py` and `web/errors.py` were being modified by
another agent while this work ran. They are **not** part of commit
`6a364c4`; only the six files listed in its stat were staged.
