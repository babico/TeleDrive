# TeleDrive — Codebase Review / Kod Tabanı Denetimi

**Denetim anı:** `main` @ `054af3a` (`fix(storage): MySQL-compatible PAB default and schema-scoped column probe`), 2026-10-26.
**Kapsam:** `teledrive/`, `web/`, `web/static/`, `tests/`, `scripts/ops/`.
**Yöntem:** `find`/`wc`, `grep`, Python AST taraması, GitHub REST API, `git diff --check`/`git apply --check` (salt-okunur).
**Not:** Denetim sırasında çalışma ağacında `.github/workflows/*`, `Dockerfile`, `docker-compose.yml`, `config.example.yaml`, `teledrive/settings.py`, `web/app.py`, `tests/meta/test_ci_workflows.py` ve `deploy/` altında başka bir süreçten gelen, commit edilmemiş değişiklikler vardı. Bu değişiklikler bu raporun kapsamı dışıdır; tüm satır numaraları yukarıdaki **commit'lenmiş `054af3a` ağacına** göredir, geçici çalışma ağacına göre kaymış olabilir.

---

## 0.1 Düzeltme durumu (2026-10-26)

Denetimden sonra kapatılan bulgular — her biri regresyon testiyle:

| Bulgu | Durum | Commit / kanıt |
|---|---|---|
| **P4** API key ile yetki yükseltme (mint/rotate/revoke) | ✅ Kapandı | `9c4769d` — delegasyon tavanı: anahtar yalnız kendi izin kümesi içinde devredebilir; `test_api_key_cannot_mint_beyond_its_own_permissions`, `..._rotation_cannot_steal_a_more_privileged_key`, `..._cannot_revoke_above_its_own_authority` |
| **P8** batch delete / CopyObject / UploadPartCopy ACL bypass | ✅ Kapandı | `9c4769d` — her batch girdisi kendi key'iyle, her iki copy yolu kaynak ACL'iyle denetleniyor; `test_batch_delete_honours_per_object_acl`, `test_copy_object_honours_the_source_object_acl` |
| **P9** ACL sahipliği devredilebilir (takeover) | ✅ Kapandı | `9c4769d` — sahiplik değiştirilemez; başka Owner adı 400; `test_block_public_acls_locks_acl_writes_to_the_owner` |
| **P11** süresi geçmiş credential reveal + presign kapsamı | ✅ Kapandı | `9c4769d` — `reveal()` expired'ı reddeder, presign `s3:GetObject` ister; `test_reveal_refuses_expired_credential` |
| **P3** fiziksel GC operator'e açık | ✅ Kapandı | `9c4769d` — GC toggle + collect artık admin-only; `test_physical_gc_is_admin_only` |
| **P7** audit kimliği spoof edilebilir | ✅ Kapandı | `4365694` — doğrulanmamış Basic adı `unverified-basic` yazılır; canlıda doğrulandı (`[unverified-basic] ... -> 401`) |
| O4 şema başlatma yarışı | ⏳ Açık | Ayrı bir migration/kilit refactor'ı gerektiriyor (§3.3) |
| P1/P2/P5/P6/P10, O1/O5/O12, A1–A4 | ⏳ Açık | Yapısal refactor; §4'teki sıraya göre ele alınmalı |

> Not: P5 (session ile bearer arasındaki yetki asimetrisi) ve P6 (legacy Basic = koşulsuz admin) **tasarım kararı** gerektirir; ikisi de geriye dönük uyumluluk sözleşmesini değiştirir, bu yüzden otomatik düzeltilmedi.

## 0. Yönetici Özeti

- **20.051 satır** üretim kodu (`teledrive/**/*.py`, `web/*.py`) ve **3.506 satır** frontend (`web/static/*.js|html`, vendor dahil; iş kodu 3.402) var. Test kodu **~23.500 satır**; test/üretim oranı sağlıklı (~1.17).
- Ancak üretim kodunun **%42'si iki dosyada**: `web/app.py` (5.031) + `web/s3.py` (3.388). Bu iki dosya 129 route ve 59+ handler taşıyor.
- SQLAlchemy **ORM olarak değil, query builder/DBAPI olarak** kullanılıyor: 0 declarative model, **9 ayrı `MetaData`**, 46 `Table`, 5 `Index`, 15 `ForeignKey`, **125 `text()` çağrısı**.
- En yüksek riskler kod hacmi değil, **yetkilendirme katmanlarının çokluğu**: aynı anda session + cookie, legacy Basic, iki ayrı bearer yolu, S3 SigV4, S3 ACL intersection ve public share token'ı devrede. Bu katmanlar arasında 3 kritik bypass ve 1 yetki yükseltme yolu bulundu.
- 3 açık PR'ın tamamı eski `main` SHA'larından açılmış. #24 hâlâ uygulanabilir (docs-only); #22 tamamen superseded; #25'in yalnızca statik SQL temizliği kurtarılmalı.

**Toplam bulgu: 76** (15 envanter + 12 ORM + 11 izin + 15 refactor + 3 PR + 20 küçük kesit).

---

## 1. Büyük Dosya Envanteri (>= 600 satır)

> Sıralama satır sayısına göre azalan. HTML dosyalarının en büyüğü `buckets.html` (325 satır) olduğu için **600+ HTML yok**; bu yüzden HTML'ler ayrı bir paragrafta ele alındı. `web/static/vendor/*` minified/vendor olduğu için satır envanterine alınmadı (Tailwind runtime 400 KB, Alpine 56 KB — §6/C19).

| # | Dosya | Satır | Tip | Bölünmeli mi? | Somut bölme önerisi |
|---|-------|------:|-----|---------------|---------------------|
| 1 | `web/app.py` | 5.031 | Python | **Evet, zorunlu** | `web/app_factory.py` + `web/routers/{auth,users,api_keys,s3_credentials,telegram,storage_buckets,storage_jobs,gc,shares,config,system}.py` + `web/security.py` + `web/logging.py` + `web/config_store.py`. 5.000 satırlık tek modül test izolasyonunu da bozuyor. |
| 2 | `web/s3.py` | 3.388 | Python | **Evet, zorunlu** | `web/s3/{router,responses,authz,bucket_controls,objects,multipart,acl,object_lock,listing,form_upload}.py`. `_handle()` tek başına ~450 satır (2821-3270). Protokol ayrıştırma zaten `teledrive/s3/*` içinde; `web/s3.py` yalnızca dispatch etmeli. |
| 3 | `tests/web/test_auth_rbac.py` | 1.437 | Test | Evet | `test_auth_*`, `test_rbac_*`, `test_admin_storage_*`, `test_telegram_*` olarak 4 dosya. |
| 4 | `web/static/app.js` | 1.184 | JS | **Evet** | Tek `app()` Alpine bileşeni tüm sayfaların state'ini taşıyor. `static/js/{http,upload,crypto,files,buckets,shares,keys,logs}.js`; her HTML yalnız kendi bileşenini yüklemeli. |
| 5 | `tests/s3/test_s3_post_policy.py` | 1.124 | Test | Evet | Presigned POST senaryoları + boto3 fixture'ları ayrılmalı; ortak fixture `conftest.py`'ye. |
| 6 | `tests/meta/test_ci_workflows.py` | 1.122 | Test | Hayır (meta) | Workflow YAML'lerini denetleyen tek dosya olması savunulabilir; yine de `test_ci_matrix.py` + `test_ci_guards.py` ayrılabilir. |
| 7 | `teledrive/storage/catalog.py` | 1.080 | Python | **Evet** | `storage/catalog/{buckets,objects,versions,acls}.py`; `BucketCatalog` ince bir facade olarak kalmalı. ACL/PAB bloğu (347-467) ve version listing (769-920) bağımsız. |
| 8 | `tests/e2e/test_database_live.py` | 1.036 | Test | Evet | Feature bazlı: schema/lease, manifest/chunk, multipart, tags/metadata, version/GC, rate-guard. Ortak parametrize fixture korunmalı. |
| 9 | `teledrive/storage/user_mode.py` | 850 | Python | **Evet** | `storage/mtproto_credentials.py` (1-327), `storage/user_runtime.py` (328-512), `storage/send_journal.py` (513-606), `storage/user_transport.py` (607-850). |
| 10 | `teledrive/s3/multipart.py` | 764 | Python | Evet | `s3/multipart/{store,parts,completion,recovery}.py`. Tamamlama lease/fence kodu ayrı test edilmeli. |
| 11 | `scripts/ops/acceptance.py` | 692 | Script | Kısmen | CLI orkestratörü kalabilir; her gate `scripts/ops/checks/*.py` olarak ayrılmalı. |
| 12 | `tests/s3/test_s3_gateway.py` | 667 | Test | Evet | `test_gateway_crud.py`, `test_gateway_listing.py`, `test_gateway_copy.py`, `test_gateway_presign.py`. |
| 13 | `tests/storage/test_storage_engine.py` | 625 | Test | Evet | Chunking, ranged read, verification, failure/retry olarak ayrılmalı. |
| 14 | `teledrive/storage/engine.py` | 611 | Python | Sınırda | Dosya bütünlüğü/digest yardımcıları (46-64) ayrılabilir; ana sınıf cohesive, bölmek zorunlu değil. |
| 15 | `teledrive/db.py` | 601 | Python | Evet | `db/schema.py` (metadata + Table'lar), `db/migrations.py`, `db/engine.py`, `db/queries.py` (Database metotları). |

**HTML notu:** `buckets.html` 325, `credentials.html` 276, `telegram.html` 270, `api-management.html` 267. Tek başına 600 değiller, fakat aynı modal/tablo/empty-state markup'ı 4 dosyada kopyalanıyor. Ortak `<template>`/Alpine component'leri veya sunucu tarafı partial'a çıkarılmalı.

---

## 2. ORM Durumu

### 2.1 Kullanım biçimi

SQLAlchemy burada **ORM değil**: declarative base, `relationship()`, `Session`/`sessionmaker` yok (0 eşleşme). Her şey Core `Table` + `select/insert/update/delete` + ham `text()`. `DBRow` (`teledrive/db.py:176`) yalnızca `Row` etrafında dict/tuple sarmalayıcı.

**Sonuç:** Unit-of-work, cascade, lazy loading, identity map ve model-seviyesi validasyon yok. Bu bir tercih olabilir; ancak 9 ayrı `MetaData` ve constructor içinde `create_all` ile birleşince tutarlılık kayboluyor.

### 2.2 Bulgular

**O1 — 9 ayrı `MetaData` (yüksek).**
`teledrive/db.py:18`, `teledrive/storage/manifest.py:21`, `teledrive/storage/catalog.py:25`, `teledrive/storage/jobs.py:28`, `teledrive/api_keys.py:19`, `teledrive/s3/credentials.py:19`, `teledrive/s3/multipart.py:32`, `teledrive/storage/mtproto_rate_guard.py:21`, `teledrive/storage/user_mode.py:27`.
Aynı veritabanındaki tablolar farklı metadata'lara dağıldığı için SQLAlchemy string `ForeignKey` çözümü yapamıyor; ilişkili tablolar arasında FK tanımlanamıyor.

**O2 — 46 `Table`, yalnızca 5 `Index`, 15 `ForeignKey` (yüksek).**
`grep -c` ile doğrulandı. Özellikle manifest/catalog/S3 metadata tablolarının çoğunda FK ve sorgu index'i yok. Bu, "foreign key var mı?" sorusunun cevabını modül modül değiştiriyor.

**O3 — 125 ham `text()` çağrısı (yüksek).**
Dağılım: `web/app.py` 87, `teledrive/storage/catalog.py` 15, `teledrive/storage/gc_collect.py` 12, `teledrive/storage/user_mode.py` 9, `teledrive/storage/engine.py` 1, `teledrive/storage/content_index.py` 1.
En yoğun alanlar: users/sessions (`web/app.py:1322-1762`), telegram sessions/channels (`1989-2740`), quota/pin/share (`3385-3922`), metrics (`3750-3860`). Bu SQL'lerin bir kısmı model tanımlarıyla çelişiyor (ör. `ON CONFLICT`).

**O4 — f-string / dinamik SQL (orta-yüksek).**
- `teledrive/db.py:488`, `:506`, `:518` — `ALTER TABLE {table_name} ADD {rendered}`. Tablo adı ve kolon render'ı iç kod kaynaklı; yine de Bandit B608 riski.
- `teledrive/storage/catalog.py:114` — `PRAGMA table_info({table})`; `:128` — `WHERE table_name = '{table}' AND table_schema = {schema}`. `table` sabit, `schema` dialect sabiti; injection pratikte yok, fakat desen kötü.
- `teledrive/storage/gc_collect.py:186` ve `:190` — `f"SELECT COUNT(*) {base} ..."`; `# nosec B608` ile bastırılmış. `base` modül sabiti olsa da bu, PR #25'in haklı olarak temizlemek istediği kod.

**O5 — Manuel ALTER'lar migration sisteminin yerine geçmiş (yüksek).**
`teledrive/db.py:475-518` (files/telegram_sessions/pending), `teledrive/storage/catalog.py:121-180` (bucket PAB/object lock), `teledrive/storage/gc_collect.py:73-89` (gc grace), `web/app.py:761-772` ve `:919-931` (users.enabled, **birebir kopya**), `teledrive/storage/content_index.py:69-79` (FTS/tsvector DDL).
Bunlar idempotent görünse de sürüm numarası, downgrade, sıra ve audit edilebilirlik yok.

**O6 — Şema başlatma yarışı (kritik).**
`db.py:544-554` yalnızca `_setup_schema` için PostgreSQL advisory lock alıyor. Fakat `BucketCatalog.__init__` (`catalog.py:201`), `ManifestStore.__init__` (`manifest.py:133`), `StorageUploadJobs.__init__` (`jobs.py:82`), `ApiKeyStore.__init__` (`api_keys.py:94`), `S3CredentialStore.__init__` (`credentials.py:86`), `MultipartStore.__init__` (`multipart.py:105`), `MtprotoRateGuard.__init__` (`mtproto_rate_guard.py:65`), `UserSessionRuntime` (`user_mode.py:516`) ve `RetainedMediaGC.__init__` (`gc_collect.py:100-101`) **kilit dışında** `create_all` çağırıyor.
İki worker aynı anda açılırsa `CREATE TABLE` yarışı ve `ensure_versioning_column` içinde çift `ALTER TABLE` görülebilir. `_versioning_column_ensured` (`catalog.py:98`) process-local olduğu için worker'lar arası koruma sağlamaz.

**O7 — Eksik / tutarsız FK'ler (yüksek).**
- `storage_published_versions.object_id` ve `.bucket` → FK yok (`catalog.py:77-83`).
- `storage_removed_versions.object_id` → FK yok (`catalog.py:86-90`).
- `storage_object_acl_grants.bucket`, `storage_bucket_acl_grants.bucket` → FK yok (`catalog.py:54-68`).
- `storage_multipart_uploads.bucket`, `.completed_object_id` → FK yok (`multipart.py:33-43`).
- `storage_multipart_parts.object_id`, `storage_multipart_etags.object_id` → FK yok (`multipart.py:44-52`, `68-72`).
- `storage_upload_jobs.bucket`, `.object_id` → FK yok (`jobs.py:29-47`).
- `user_sessions.user_id` → FK yok (`db.py:167-173`).
- `share_links.bucket`, `bucket_account_pins.account`, `files.tg_account` → string, FK yok.
Sonuç: `delete_bucket` sonrası yetim satırlar oluşabiliyor (O10).

**O8 — Eksik index'ler (orta-yüksek).**
- `storage_object_aliases.source_object_id`: PK `(object_id, source_object_id)` olduğu için GC'nin `WHERE a.source_object_id = o.id` sorgusu (`gc_collect.py:179-180`, `:370`, `:445`) index kullanamaz. **En somut eksik index.**
- `storage_upload_jobs(state, lease_until)`: `claim_next` (`jobs.py:180-187`) her turda tarıyor.
- `storage_multipart_uploads(bucket, state)`: `delete_bucket` ve stale listesi tarıyor.
- `user_sessions(user_id)`: kullanıcı silmede/oturum iptalinde tam tarama.
- `storage_gc_queue(enqueued_ns)`: grace sorgusu.
Mevcut 5 index: `files(status)`, `files(tg_account)`, `published_versions(bucket,key_hash,committed_ns)`, `storage_objects(bucket)`, `storage_objects(status)`.

**O9 — MySQL sözleşmesi kodla çelişiyor (kritik, çünkü README/CI MySQL'i destekliyor).**
- `web/app.py:3735` ve `:3902` — `ON CONFLICT (bucket) DO UPDATE` (SQLite/PostgreSQL; MySQL'de syntax error).
- `web/app.py:3634` — `INSERT OR IGNORE` (SQLite-only).
- `web/app.py:3598-3602` — `LIKE '%.' || :ext` (SQLite/PostgreSQL; MySQL `CONCAT` ister).
- `teledrive/storage/content_index.py:61-64` — MySQL'de içerik arama sessizce devre dışı.
- `teledrive/storage/catalog.py:119-128` MySQL şema filtresi eklenmiş (son commit), fakat yukarıdaki endpoint'ler hâlâ kırık.
`tests/e2e/test_database_live.py` MySQL'i parametrize ediyor ama quota/pin/share/reindex endpoint'lerini kapsamıyor.

**O10 — `delete_bucket` yetim metadata bırakıyor (yüksek).**
`catalog.py:1040-1080` yalnızca `storage_bucket_tags`, `storage_bucket_lifecycle`, `storage_bucket_cors` siliyor. Şunlar kalıyor:
`storage_bucket_acl_grants`, `storage_object_acl_grants`, `bucket_quotas`, `bucket_account_pins`, `share_links` (bucket bazlı kayıtlar). Aynı bucket adı yeniden oluşturulursa eski ACL/quota/pin/share aniden etkinleşir. **Bu bir güvenlik hatasıdır**, sadece kozmetik değil.

**O11 — Object-lock default retention publish ile atomik değil (yüksek).**
`catalog.py:952` ve `:990` head/published version'ı commit ediyor; `apply_default_lock` ancak ondan sonra ayrı transaction'da çağrılıyor (`:955`, `:991`). İki adım arasında crash olursa bucket "Object Lock enabled + default retention" olmasına rağmen yeni versiyon **kilitsiz** kalır. WORM iddiası bu yarışta tutmuyor. `test_s3_object_lock.py:138` yalnızca mutlu yolu test ediyor.

**O12 — Tutarlılık planı (küçükten büyüğe).**
1. **Dondur ve ölç:** Mevcut `MetaData`'lardan `docs/SCHEMA.md` üret; tablo/kolon/FK/index envanterini CI'da karşılaştır.
2. **Alembic baseline:** Tek `alembic/` dizini, `render_as_batch=True` (SQLite), `compare_type=True`, `compare_server_default=True`. İlk revision mevcut şemayı "baseline" olarak işaretlesin.
3. **`MetaData` birleştirme (domain domain):** `teledrive/db/schema.py` tek metadata; `core` → `manifest` → `catalog` → `s3` → `jobs` → `auth`. Tablo adları değişmesin; modüller yalnız `Table` nesnelerini import etsin.
4. **`create_all`'ları tek noktaya taşı:** Tüm constructor'lardan kaldır; `connect_database`/`_setup_schema` içinde, PostgreSQL advisory lock + MySQL `GET_LOCK` + SQLite `BEGIN IMMEDIATE` ile koru.
5. **Manuel ALTER'ları revision'a çevir:** `ensure_versioning_column`, `_ensure_grace_column`, users.enabled bloğu. Bir sürüm boyunca no-op shim bırak.
6. **FK/index migration sırası:** `storage_buckets` → `storage_objects` → `storage_object_heads` → `storage_published_versions`/`storage_removed_versions` → `storage_chunks`/`storage_object_aliases` → S3 metadata → jobs/multipart → auth. Önce yetim satır temizliği; PostgreSQL'de `NOT VALID` + `VALIDATE`, SQLite'da batch rebuild, MySQL'de online DDL.
7. **Ham SQL azaltma:** Önce quota/pin/share/users (tekrar eden, düşük risk), sonra GC metrics. Her modül kendi store'unu kullansın.
8. **Test:** 3 backend × migration upgrade, concurrent startup (2 process), orphan-FK fail testi, MySQL quota/reindex smoke.

**Riskler:** SQLite tablo rebuild kilitleri; MySQL'de FK için index zorunluluğu; mevcut yetim satırlar FK eklemeyi bloke eder; büyük tablolarda uzun kilit; `create_all` kaldırılırken test fixture'larının bozulması; Alembic downgrade'in Telegram verisini etkilememesi (metadata-only olduğu için görece güvenli).

---

## 3. API Key / İzin Düğümü

### 3.1 Mevcut katmanlar

| Katman | Giriş noktası | Kimlik | Yetki kontrolü | CSRF | Not |
|--------|---------------|--------|----------------|------|-----|
| Browser session (cookie veya `td_sess_` bearer) | `web/app.py:518` `require_auth` → `_get_current_user` (`:423`) | `user_sessions` tablosu, SHA-256 digest | Yalnızca `_required_roles` (`:469`) path sezgisi | Handler içinde `_same_origin` (`:298`), 51 çağrı | Route bazlı izin yok; viewer tüm GET'leri okur. |
| Legacy HTTP Basic | `web/app.py:556-573` | Tek `WEB_USER`/`WEB_PASSWORD` sabiti | Başarılıysa **role=admin** | Handler `_same_origin` | DB kullanıcısı değil; tüm RBAC'ı bypass eder. |
| REST API key (9 eski endpoint) | `require_api_scope` (`:1272`) | `td_live_` + `api_credentials.digest` | `ApiKeyStore.authorize(token, required)` (`api_keys.py:145`) | Yok (cookie değil) | `required` string'i handler'da sabit yazılı. |
| Genel API key (admin dahil tüm route'lar) | `require_auth` (`:523-547`) | aynı store | `PermissionRegistry.permission_for` (`permissions.py:186`) + `authorize` | Handler `_same_origin` | Role policy uygulanmaz; anahtarın izni neyse o. |
| S3 SigV4 header | `verify_header_signature` (`sigv4.py:279`) | `access_key` | `S3CredentialStore.resolve(access_key, action)` (`credentials.py:120`) | N/A | `action` `web/s3.py:2836-3050` dev if/elif'te seçilir. |
| S3 presigned | `_presigned_signature` (`sigv4.py:84`) | aynı | expiry + resolve | N/A | Presign URL üretimi admin route'unda. |
| S3 POST policy | `_handle_form_upload` (`web/s3.py:701`) | policy credential | `verify_post_policy` + `resolve(...,"s3:PutObject")` + ACL (`:740-750`) | N/A | Browser form upload. |
| S3 resource ACL | `_acl_allows` (`web/s3.py:1889`) → `acl.permits` (`acl.py:67`) | access_key | `own scopes ∩ grants` | N/A | Yalnızca daraltır; ACL yoksa açık baseline. |
| Public share | `_load_active_share`/`_stream_share` (`web/app.py:4909-4932`) | token | expiry + download_count + password | N/A | Atomik slot claim var. |
| WebSocket log | `logs_stream` (`web/app.py:2915`) | cookie session | yalnız `_get_current_user` | N/A | Role/route policy yok; viewer logları izleyebilir (GET log ile tutarlı). |

### 3.2 Bulgular

**P1 — Üç ayrı izin kataloğu (yüksek, drift).**
Aynı 9 REST izni üç yerde:
1. `teledrive/api_keys.py:31-41` `ENDPOINT_PERMISSIONS`
2. `web/permissions.py:22-32` `CURATED_PERMISSIONS`
3. `web/app.py:4632/4646/4698/4777` handler'larda gömülü string'ler.
Ayrıca S3 action listesi `teledrive/s3/credentials.py:31-54` ve `web/s3.py:2836-3050` olarak iki yerde. Yeni bir route eklendiğinde yalnız registry güncelleniyor; eski 9 endpoint'in string'i ve S3 action mapping'i elle senkron kalıyor.

**P2 — Path-sezgisi tabanlı rol policy (yüksek).**
`_required_roles` (`web/app.py:469-494`) method + `request.url.path` ile karar veriyor; route decorator'ında rol yok. `if method == "GET": return None` satırı (`:483-484`) tüm GET'leri viewer'a açıyor. Sonuç:
- `/api/v1/admin/users` GET → admin (önce kontrol edildiği için) ama `/api/v1/admin/storage/buckets/{b}/quota` GET → **viewer** (quota kontrolü `:492` GET dönüşünden sonra).
- Yeni bir `/api/v1/admin/...` route'u eklenirse ve path deseni listeye girmezse varsayılan `_ROLE_WRITE` olur; admin-only olması gereken bir route operator'e açılabilir.
- Alias normalizasyonu (`:478-480`) yalnız `/api/*` → `/api/v1/*`; başka bir prefix/encoding durumu test edilmiyor.

**P3 — Fiziksel GC "owner gate" değil, operator gate (kritik).**
`PUT /api/v1/admin/storage/gc` (`web/app.py:3996`) ve `POST .../gc/collect` (`:4022`) `_required_roles` sonunda `_ROLE_WRITE` döndürüyor (`:494`). Yani **operator** GC'yi açabilir ve `confirm="PHYSICAL-GC"` / `"DELETE-RETAINED"` yazarak Telegram medyasını silebilir. Kod ve doküman "owner decision" diyor; fiiliyet operator. API key ile de aynı route çağrılabilir (bearer role policy'yi atlar). `tests/storage/test_gc_collect.py:161` yalnız admin fixture'ı ile test ediyor; operator reddi testi yok.

**P4 — API key ile key mint/rotate yetki yükseltmesi (kritik).**
`POST /api/v1/admin/keys` (`web/app.py:1556-1575`) gelen `payload.scopes`'u, isteği yapan anahtarın kendi izinleriyle karşılaştırmadan `ApiKeyStore.create(..., extra_allowed=route_permissions)`'a veriyor. `require_auth` bearer yolunda role policy yok (`:519-547`).
Sonuç: yalnızca `post:/api/v1/admin/keys` izni olan bir anahtar, kendisine **herhangi bir route izni** (ör. `delete:/api/v1/admin/users`, `post:/api/v1/admin/s3/credentials`) olan yeni bir anahtar üretebilir. Aynı şekilde `POST .../keys/{identifier}/rotate` (`:1590-1602`) path parametresiyle **başka bir anahtarı** rotate edip yeni secret'ı alabilir; hedef anahtarın izinleri daha yüksekse tam ele geçirme olur. `tests/web/test_per_route_permissions.py:85` mint'i test ediyor ama escalation'ı değil.

**P5 — Session ile bearer arasında asimetri (yüksek).**
Viewer session'ı tüm GET API'lerini okur (config redacted, loglar, tüm bucket/object metadata, GC audit). Aynı kullanıcı için üretilen API key ise **her route için ayrı izin** ister. Yani "viewer" kavramı iki farklı yetki modeline karşılık geliyor. Bu, hem dokümantasyon hem test açısından kafa karıştırıcı; ayrıca session çalınması durumunda saldırganın okuma yüzeyi çok geniş.

**P6 — Legacy Basic = koşulsuz admin (yüksek).**
`web/app.py:557-572`: `WEB_PASSWORD` eşleşirse `role="admin"` atanıyor. Bu, DB'deki kullanıcı/rol sistemini tamamen atlar. `WEB_PASSWORD` zorunlu olduğu için pratikte her deployment'ta ikinci bir "root" yolu var. Basic'in test/CLI uyumluluğu için kalması savunulabilir; fakat audit'te ayrı principal olarak işaretlenmeli ve admin-only route'larda ek guard görmeli.

**P7 — Audit kimliği spoof edilebilir (orta-yüksek).**
`_extract_user` (`web/app.py:181-228`) Basic header'ı **şifreyi doğrulamadan** decode edip kullanıcı adını döndürüyor (`:205-213`). `_audit_log_middleware` (`:1044-1045`) bu değeri log'a yazıyor. Yani `Authorization: Basic YWRtaW46eA==` gönderen herkes, başarısız bir istekte bile audit log'a "admin" yazdırabilir. Ayrıca `name_for_token` revoked/expired kontrolü yapmadığı için iptal edilmiş anahtar adı da log'da görünür. Adli izlenebilirliği bozar.

**P8 — S3 ACL, batch delete ve copy source'da uygulanmıyor (kritik).**
`_handle` içindeki ACL gate (`web/s3.py:3147-3157`) `key if separator else None` kullanıyor. Batch delete URL'i bucket path'idir (`POST /bucket?delete`), dolayısıyla `key=None` olur ve yalnız **bucket ACL** değerlendirilir; `_handle_batch_delete` (`:820-898`) her key için object ACL kontrolü yapmaz. Object ACL ile "sadece bu key" kısıtlanmış bir credential, bucket'ta WRITE grant'ı varsa o key'i silebilir.
Aynı şekilde `_handle_copy_object` (`:2282-2400`) kaynak için yalnız `store.resolve(owner,"s3:GetObject")` kontrolü yapıyor; `catalog.acl_grants_for(src_bucket, src_key)` ve `acl_permits` **çağrılmıyor**. Kaynak object ACL'i ile erişimi kapatılmış bir nesne, GetObject scope'u olan credential tarafından kopyalanabilir. Multipart `UploadPartCopy` (`:1762-1785`) da aynı deseni taşıyor.

**P9 — S3 ACL sahipliği devredilebilir (kritik).**
`_validated_acl` (`web/s3.py:1915-1933`) dokümandaki `Owner` alanını çağırana eşit olmaya zorlamıyor; yalnız "aktif credential" olmasını istiyor. `BlockPublicAcls` kontrolü (`:1960-1965`, `:1999-2004`) yalnız **stored owner varsa** devreye giriyor; ilk ACL yazımında stored owner yok. Dolayısıyla `s3:PutBucketAcl` izni olan herhangi bir credential, `Owner=<kendisi>` ve grant seti ile ACL yazıp gerçek bucket sahibini kilitleyebilir. `tests/s3/test_s3_acl.py:182` yalnız stored-owner senaryosunu test ediyor.

**P10 — `extra_allowed` / `admin:*` / public route'lar (orta).**
`extra_allowed` yalnızca **issue** anında (`api_keys.py:97-110`) kullanılıyor; `authorize` sırasında route registry'ye karşı yeniden doğrulama yok. `LEGACY_SCOPE_EXPANSION["admin:*"]` yalnızca 9 REST iznini açıyor (`api_keys.py:44-55`), yani isim "admin" olsa da yeni route'ları kapsamıyor. Ayrıca `PermissionRegistry` public olmayan `/api/v1/auth/login` gibi route'ları da kataloğa alıyor (`permissions.py:126-142` sadece belirli prefix'leri public sayıyor); login'e izin vermek anlamsız ve katalog gürültüsü.

**P11 — S3 credential reveal/presign doğrulamaları eksik (orta).**
`S3CredentialStore.reveal` (`credentials.py:153-173`) revoked kontrolü yapıyor ama **expiry kontrolü yapmıyor**; süresi geçmiş credential'ın secret'ı reveal edilebiliyor. `admin_presign_object` (`web/app.py:3317-3325`) `credential_id` verilirse `s3:GetObject` izni olup olmadığını kontrol etmeden reveal ediyor; URL daha sonra resolver'da reddedilir ama gereksiz secret kullanımı ve yanıltıcı hata olur. Ayrıca S3 credential issue/update/revoke (`:4533-4618`) audit log üretmiyor; yalnız reveal logluyor (`:4571`).

### 3.3 Tek kanonik izin yolu önerisi

`web/security.py` içinde tek bir karar noktası:

```python
@dataclass(frozen=True)
class Principal:
    kind: Literal["session", "basic", "api_key", "s3", "share", "anonymous"]
    subject: str
    roles: frozenset[str]
    permissions: frozenset[str]

def authenticate(request) -> Principal | None: ...
def authorize(principal, method, path, *, resource=None) -> None: ...
```

Kurallar:
1. **Kimlik:** Session → `_get_current_user`; Basic → yalnızca sabit kimlik ve **doğrulanmış** parola; API key → digest + scopes; S3 → access_key + action.
2. **İzin:** Session için `ROLE_PERMISSIONS` haritası (viewer/operator/admin) route registry'deki permission adlarına genişler. Bearer için `expand_scopes`. Böylece iki taraf da aynı `authorize(principal, permission)` fonksiyonundan geçer.
3. **Route deklarasyonu:** `Depends(require("get:/api/v1/admin/keys", roles={"admin"}))`; path-sezgisi kaldırılır.
4. **CSRF:** Yalnızca cookie tabanlı principal'lar için tek dependency; bearer/S3 için uygulanmaz.
5. **S3:** `authorize` önce identity policy'yi (credential scope), sonra resource policy'yi (ACL intersection) çağırır. Batch delete ve copy source, her key/kaynak için ayrı `authorize(..., resource=(bucket,key))` yapar.
6. **Audit:** `request.state.principal` yalnızca doğrulanmış principal'dan yazılır; header'dan yeniden türetilmez.
7. **Katalog:** `ENDPOINT_PERMISSIONS` + `CURATED_PERMISSIONS` tek dosyada birleşir; S3 action map'i `credentials.PERMISSIONS`'tan üretilir.

---

## 4. En Değerli 15 Refactor (risk-azaltma / efor)

| # | Yer | Problem | Somut aksiyon | Efor | Koruyan test |
|---|-----|---------|---------------|------|---------------|
| 1 | `web/app.py:1556-1602` | API key mint/rotate ile yetki yükseltme | Mint/rotate'te `request.state` principal'ının izin kümesini alt küme kontrolünden geçir; `admin:*` yoksa hedef izinleri reddet | **S** | `tests/web/test_per_route_permissions.py:60-105`, `tests/web/test_api_keys.py` (escalation testi ekle) |
| 2 | `web/s3.py:3147-3157`, `:820-898`, `:2282-2400` | Batch delete ve copy source object ACL'i atlıyor | Her key/kaynak için `_acl_allows` çağır; batch'te per-entry `AccessDenied` döndür | **M** | `tests/s3/test_s3_acl.py`, `test_s3_batch_delete.py`, `test_s3_copy.py` (yeni bypass testleri) |
| 3 | `web/app.py:469-494`, `:3996`, `:4022` | Fiziksel GC operator'e açık | `/admin/storage/gc*` için `roles={"admin"}`; GC collect'te ayrıca re-auth/owner onayı | **S** | `tests/storage/test_gc_collect.py:161` (operator reddi ekle) |
| 4 | `teledrive/storage/catalog.py:1040-1080` | Bucket silme ACL/quota/pin/share yetimleri | Silmeden önce tüm bucket-scoped tabloları temizle; FK/cascade ekle | **S** | `tests/e2e/test_database_live.py:439` (ACL/quota/pin/share cleanup ekle) |
| 5 | `web/s3.py:1915-1933` | ACL Owner devredilebilir | `acl_owner` yalnız çağıran olabilir; ilk yazımda da owner zorunlu | **S** | `tests/s3/test_s3_acl.py:182` (owner transfer reddi) |
| 6 | `web/app.py:181-228`, `:1044` | Audit kimliği Basic header'dan spoof | `_extract_user`'ı kaldır; `request.state.principal` kullan | **S** | `tests/web/test_security.py` (spoof denemesi) |
| 7 | `teledrive/db.py:470-518`, tüm `__init__`'ler | Şema init yarışı ve dağınık migration | Tüm `create_all`/ALTER'ları tek `_setup_schema` altında kilitle; Alembic'e geç | **M** | `tests/e2e/test_database_live.py` + yeni concurrent-startup testi |
| 8 | `web/app.py:3598-3634`, `:3735`, `:3902` | MySQL'de kırık SQL | `ON CONFLICT` → dialect-aware upsert; `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING`/`INSERT IGNORE`; `||` → `CONCAT` | **M** | MySQL parametrize `test_database_live.py` + quota/reindex smoke |
| 9 | `teledrive/api_keys.py:31-55`, `web/permissions.py:22-32`, `web/app.py` handler'ları | 3 kopya izin kataloğu | Tek `permissions_catalog.py`; handler'lar sabit string yerine registry'den alsın | **M** | `tests/web/test_per_route_permissions.py:36` |
| 10 | `web/app.py:518-579` | Session/Basic/bearer üç ayrı karar yolu | §3.3'teki `Principal`/`authorize` modeli | **L** | `test_auth_rbac.py`, `test_per_route_permissions.py` |
| 11 | `web/app.py` (5.031) | Devasa router dosyası | Router paketlemesi + `create_app()` factory | **L** | Tüm `tests/web` suite |
| 12 | `web/s3.py` (3.388) | Devasa S3 dispatch | Handler modülleri; `_handle` yalnız yönlendirsin | **L** | Tüm `tests/s3` suite |
| 13 | `web/app.py` 87 `text()` | ORM bypass, dialect kırılganlığı | users/sessions/quota/pin/share için Core store katmanı; raw SQL'i yalnız kompleks raporlarda bırak | **L** | `test_auth_rbac.py`, `test_rest_api.py`, `test_database_live.py` |
| 14 | `teledrive/storage/catalog.py:77-90`, `manifest.py:56-96` | Eksik PK/FK/index | `published_versions.object_id/bucket`, `removed_versions.object_id`, `aliases.source_object_id` index; FK migration | **M** | `test_storage_catalog.py`, `test_database_live.py` |
| 15 | `teledrive/storage/user_mode.py:46-93` | Ölü/çift tanımlı fonksiyonlar | `_session_from_file` ve ilk `_session_from_file_for`'u sil; `_split_list` kullanılmıyorsa kaldır | **XS** | `tests/storage/test_storage_user_mode.py` |

---

## 5. PR Triyajı

GitHub API (`/repos/babico/TeleDrive/pulls/{22,24,25}` + `/files`) ve yerel `git apply --check` ile doğrulandı. API `mergeable` alanı sorgu anında `unknown` döndü; bu yüzden metin çakışması yerel apply-check ile ölçüldü.

| PR | Başlık | Base SHA | Yaş | Dosya | Çakışma | Öneri |
|----|--------|----------|-----|-------|---------|-------|
| **#22** | fix(ci/docs): verify Telethon storage roadmap and repair config-only job regression | `3aa70d1` (main'den **23 commit** geride) | 3 gün | 12 dosya, +239/−43, 9 commit (9 docs/config + 3 test) | `tests/storage/test_storage_jobs.py:205` apply-check **FAIL**; 7 dosya main'de değişmiş | **CLOSE** |
| **#24** | docs(ci): count six automatic workflows plus manual endurance correctly | `8c40325` (13 commit geride) | 2 gün | 6 docs, +7/−7, 1 commit | Apply-check **temiz**; metinsel çakışma yok | **REBASE + MERGE** |
| **#25** | fix(gc/security): restore CI gate and reconcile Telethon-only operational docs | `65e0b64` (12 commit geride) | 2 gün | 5 docs + `gc_collect.py`, +32/−17, 2 commit | `gc_collect.py:101` apply-check **FAIL** (Phase A rewrite); docs kısmı temiz | **EXTRACT-PARTS + CLOSE** |

### #22 — CLOSE

- Test düzeltmesi main'de **farklı biçimde** zaten yapıldı: `tests/storage/test_storage_jobs.py:208-217` artık config-only root ve 422/503 ayrımını test ediyor. PR'ın aynı dosyadaki hunk'ı bu yüzden uygulanmıyor.
- `docs/VERIFICATION_2026-10-22.md` 3aa70d1 anına ait bir anlık görüntü; sonrasında gelen 23 commit (Phase A–E, ACL, PAB, object lock, per-route permissions) bu raporu **yanlış** hale getiriyor.
- `TODO.md`/`README` değişiklikleri daha yeni metadata-parity metinleriyle çakışıyor.
- **Gerekçe:** "En güvenli ve en yeniyi koruyan yön" — eski roadmap anlatısını geri getirmemek. Çıkarılacak bağımsız bir parça yok.

### #24 — REBASE + MERGE

- Dokümanlar hâlâ yanlış: `docs/CI_WORKFLOWS.md:21` "first seven workflows", `docs/TELETHON_STORAGE.md:172` "seven mandatory workflows", `docs/IMPLEMENTATION_STATUS.md:21` "seven workflows", `TODO.md:9` "six of seven".
- PR tam olarak bunları düzeltiyor; apply-check mevcut ağaca temiz uygulanıyor. Riski çok düşük.
- **Gerekçe:** Yeni işi regresse etmiyor, yalnızca operatör dokümanını gerçeğe yaklaştırıyor. Merge öncesi workflow sayısını güncel commit'e göre bir kez daha doğrula (çalışma ağacındaki CI değişiklikleri sayıyı etkileyebilir).

### #25 — EXTRACT-PARTS + CLOSE

- `gc_collect.metrics` hâlâ `f"SELECT COUNT(*) {base}"` kullanıyor (`gc_collect.py:186`, `:190`) ve `# nosec B608` ile bastırıyor. PR'ın statik SQL temizliği **değerli**.
- Ancak PR'ın base'i Phase A öncesi; `gc_collect.py` o zamandan beri yeniden yazıldı (queue/grace/lifecycle). Rebase etmek yeni GC kodunu regresse etme riski taşıyor.
- **Gerekçe:** Statik SQL düzeltmesini güncel `metrics()` üzerine elle uygula (base fragment'ini kaldır, iki sorguyu da tam yaz), docs düzeltmelerini #24'e kat, sonra #25'i superseded olarak kapat. Owner kuralı gereği eski dalı körlemesine merge etme.

---

## 6. Death by 1000 Cuts

**C1 — Çift tanımlı `_session_from_file_for` (ölü kod).**
`teledrive/storage/user_mode.py:51-60` ve `:83-93` aynı isimle iki kez tanımlı; ikincisi birincisini eziyor. İlk tanım hiç çalışmıyor. `tests/storage/test_storage_user_mode.py` bunu yakalamıyor.

**C2 — Kullanılmayan `_session_from_file` ve `_split_list`.**
`user_mode.py:46` ve `:63` hiçbir yerden çağrılmıyor (`grep` ile doğrulandı). Silinmeli.

**C3 — `users.enabled` ALTER bloğu iki kez kopyalanmış.**
`web/app.py:760-772` ve `:919-931` birebir aynı. Ayrıca `enabled` zaten `teledrive/db.py:151` metadata'sında var; migration `db._setup_schema`'ya taşınmalı.

**C4 — Quota kontrolünde aynı pahalı sorgu iki kez.**
`web/app.py:3702` ve `:3706` ayrı ayrı `_bucket_current_usage` çağırıyor; tek çağrı yeterli.

**C5 — Telegram metrikleri için 4+ ayrı GROUP BY.**
`web/app.py:2144-2170` (sessions listesi) ve `:3824-3860` (Prometheus) aynı tabloları ayrı ayrı tarıyor. Tek bir `telegram_usage_snapshot()` helper'ına alınmalı.

**C6 — Config üç kez parse ediliyor.**
`settings_bind_address` (`:88`), `settings_web_port` (`:97`), `settings_s3_port` (`:106`) her biri `load_settings(uploader.load_config(...))` yapıyor; `web/unified.py:55-57` üçünü arka arkaya çağırıyor. Tek `load_service_settings()` yeterli.

**C7 — Key hash mantığı iki yerde.**
`BucketCatalog._keyhash` (`catalog.py:212`) SHA-256 hex; `web/app.py:3683` aynı hesabı elle yapıyor. Ortak helper'a alınmalı; aksi halde biri değişince quota lookup sessizce bozulur.

**C8 — Geniş `except Exception: pass` sayısı yüksek.**
Üretimde 90 `except Exception` var; özellikle `web/app.py:203`, `:212`, `:225`, `:459`, `:2160-2170`, `:3824-3860` hataları yutuyor. Auth yolunda yutulan hata "kimlik yok"a dönüşüyor; metrics yolunda sessizce sıfır gösteriyor. En azından `_log` ile tip bazlı kayıt zorunlu olmalı.

**C9 — Audit log kimliği doğrulanmamış header'dan.**
Bkz. P7. `_extract_user` Basic'i şifresiz decode ediyor.

**C10 — S3 credential issue/update/revoke audit'siz.**
`web/app.py:4533-4618` hiç `_log` çağırmıyor; yalnız reveal (`:4571`) logluyor. Secret üretimi ve izin değişimi audit edilmeli.

**C11 — `reveal` expiry'yi yok sayıyor.**
`credentials.py:153-173` yalnız `revoked` bakıyor. `test_s3_admin.py:129` yalnız aktif credential reveal'ini test ediyor.

**C12 — Presign credential seçimi izin/expiry doğrulamıyor.**
`web/app.py:3317-3325` `credential_id` verilirse `s3:GetObject` ve expiry kontrolü yapmadan `reveal` ediyor.

**C13 — `delete_bucket` yetimleri.**
Bkz. O10. Özellikle ACL grant'ları yeniden oluşturulan bucket'ta eski sahipliği geri getirir.

**C14 — MySQL SQL sızıntıları.**
Bkz. O9. `web/app.py:3598`, `:3634`, `:3735`, `:3902`.

**C15 — İçerik arama MySQL'de sessizce yok.**
`teledrive/storage/content_index.py:61-64` MySQL'de hiçbir şey yapmadan dönüyor; `/admin/storage/search` boş sonuç veriyor. Kullanıcıya "desteklenmiyor" demek yerine sessiz boş dönüş var.

**C16 — Public route'lar izin kataloğunda.**
`/api/v1/auth/login` ve `/api/auth/login` registry'ye giriyor (`permissions.py:126-142` public listesinde değil), oysa `require_auth` kullanmıyorlar. Katalogda anlamsız izinler üretiyor.

**C17 — `GROUP_DESCRIPTIONS` elle bakım.**
`web/permissions.py:36-113` route listesini elle taşıyor; yeni route eklendiğinde açıklama "API endpoints under ..." fallback'ine düşüyor. Registry'den üretilebilir.

**C18 — Frontend her sayfada 400 KB Tailwind runtime + 56 KB Alpine yüklüyor.**
`web/static/index.html:7-8` (ve diğer 10 HTML) `/static/vendor/tailwindcss.js` + `alpine.min.js` çekiyor. Tailwind JIT runtime production'da çalışıyor; CSP'de `unsafe-eval` gerektiriyor (`web/app.py:1099`). Build-time CSS + küçük component JS'e geçilmeli.

**C19 — `app.js` tek Alpine bileşeni.**
1.184 satır, tüm sayfaların state'ini ve upload/crypto/log akışını taşıyor. Sayfa bazlı bileşenlere bölünmeli; aksi halde her sayfa gereksiz kod yüklüyor.

**C20 — Test boşlukları (tricky paths).**
Aşağıdakiler için test yok:
- API key mint/rotate escalation (P4),
- operator'ün GC açması (P3),
- batch delete/copy source ACL bypass (P8),
- ACL owner transfer (P9),
- concurrent schema init / double ALTER (O6),
- MySQL quota/pin/reindex (O9),
- audit identity spoof (P7),
- `publish` + default lock crash penceresi (O11),
- bucket delete sonrası ACL/quota/pin/share temizliği (O10).

**Olumlu not:** Kod içinde `TODO`/`FIXME`/`XXX`/`HACK` marker'ı **yok** (yalnız `teledrive/db.py:75` yorumunda "see TODO"). Teknik borç `TODO.md`'de (41 KB) ve davranışta; kod içi işaretçi disiplini iyi.

---

## 7. Önerilen Uygulama Sırası

1. **Hafta 1 (S):** P4 (key escalation), P3 (GC role), P9 (ACL owner), P7 (audit spoof), O10 (bucket delete), O11 (default lock transaction).
2. **Hafta 2 (M):** P8 (batch/copy ACL), O6 (schema lock), O9 (MySQL SQL), O8 (alias index).
3. **Hafta 3–4 (M/L):** O1/O5/O12 (tek metadata + Alembic), P1/P2/P10 (tek izin kataloğu), §3.3 canonical auth.
4. **Sürekli:** `web/app.py` ve `web/s3.py` router bölünmesi; her yeni route ile birlikte registry testi ve en az bir negatif yetki testi.

---

## 8. Sonuç

**Yazılan dosya:** `docs/CODEBASE_REVIEW.md`
**Toplam bulgu:** **76** (15 envanter + 12 ORM + 11 izin + 15 refactor + 3 PR + 20 küçük kesit).

**En yüksek değerli 5 madde:**
1. **API key mint/rotate yetki yükseltmesi** (`web/app.py:1556-1602`) — tek bir düşük yetkili anahtar, tüm admin yüzeyine anahtar üretebiliyor.
2. **S3 ACL bypass'ları** (`web/s3.py:820-898`, `:2282-2400`) — object ACL, batch delete ve copy source'da uygulanmıyor.
3. **Fiziksel GC operator'e açık** (`web/app.py:469-494`, `:3996`, `:4022`) — "owner decision" fiilen operator/API-key gate.
4. **Şema başlatma yarışı** (`db.py:544-554` vs tüm `__init__` `create_all`'ları) — çok worker'lı açılışta çift ALTER/duplicate table riski.
5. **Bucket silmede yetim ACL/quota/pin/share** (`catalog.py:1040-1080`) — aynı adla yeniden oluşturulan bucket eski güvenlik metadata'sını geri getiriyor.

> Not: #1–#5'in tamamı **S/M** eforla düzeltilebilir; hiçbiri büyük refactor gerektirmiyor. Büyük refactor (app.py/s3.py bölünmesi, MetaData birleştirme) bu güvenlik düzeltmelerinden **sonra** yapılmalı.
