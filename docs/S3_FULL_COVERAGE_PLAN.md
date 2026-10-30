# TeleDrive — Full S3 Operation Coverage Plan

> **BU PLAN TAMAMLANDI — tasarım kaydı olarak tutuluyor, açık iş değil.**
>
> **Nihai durum: 114 supported / 0 partial / 2 unsupported — 116 operasyon.**
> Aşağıdaki 110/2/4 satırı planın yazıldığı andaki durumdur (yazıldığı anda
> doğruydu). Sonradan iki şey değişti:
>
> 1. Kalan iki "partial" bir tasarım kararı değil **bug**'tı:
>    `GetBucketAccelerateConfiguration` `<TransferAcceleratedStatus>` (iç enum
>    adı) yazıyordu, botocore'un şeması ise tek üye `Status` — boto3 belgeyi
>    boş dict olarak parse ediyordu. `GetBucketRequestPayment` zaten doğruydu
>    ve artık gerçek bir boto3 istemcisiyle kanıtlanıyor.
> 2. "İmkânsız" sayılan iki operasyon dürüst bir alt seviyede mümkündü:
>    `ListDirectoryBuckets` (directory bucket yoksa gerçek AWS cevabı: boş
>    200) ve `CreateSession` (isim sınıfına göre dürüst red: 400/404).
>
> `GetObjectTorrent` (seeder yok) ve `WriteGetObjectResponse` (Lambda
> runtime yok) kalıcı olarak unsupported. Yetkili envanter
> [S3_SPECS](S3_SPECS.md) ve `teledrive/s3/operation_manifest.json`.

**Durum (plan yazıldığında):** 110 supported / 2 partial (0 by code) / 4 unsupported — 116 operasyon.
**Hedef:** 112 supported / 0 partial / 4 unsupported (96.5%) — pratikte
ulaşılan dürüst son durum **110 supported / 2 partial / 4 unsupported**;
`GetBucketRequestPayment` ve `GetBucketAccelerateConfiguration` tasarım
gereği partial kalır (billing/edge yok), bu yüzden 112'lik hedef yalnız bu
iki read probe da "supported" sayılırsa anlamlıdır.
**Kural:** her operasyonun arkasında GERÇEK bir state veya GERÇEK bir iş olacak.
"Kabul et ve yut" yasak; yapılamayan dürüstçe reddedilir.

Bu doküman 56 kalan operasyonun her biri için somut, dürüst bir implementasyon
yolu tanımlar. Sıralama (değer / efor) oranına göredir; her faz bağımsız
sevkiyat edilebilir ve kendi CI doğrulamasını taşır.

---

## Durum (2026-10-28)

| Faz | Kapsam | Op | Durum |
|---|---|---|---|
| Başlangıç | — | — | 60 supported / 8 partial / 48 unsupported |
| **L** | Policy engine, ownership, ABAC, PAB delete | 8 | ✅ `4831a67` |
| **N1–N3** | Analytics/inventory/metrics config + gerçek rapor üretimi | 12 | ✅ `4831a67` |
| **O** | RenameObject, SelectObjectContent, RestoreObject, annotations, RequestPayment/Accelerate yazma | 9 | ✅ `4831a67` + `2e461d1` (gerçek AWS wire shape'leri) |
| **Ara toplam** | | **29** | **89 supported / 7 partial / 20 unsupported** |
| **N5 + O1** | Erişim sayacı, intelligent-tiering, RestoreObject'ın gerçek arşiv yolu | 6 | ✅ `f341691`, `<Tiering>` düzeltmesi `45d40ff` |
| **O3** | Bucket metadata journal (gerçek mutasyon jurnali) | 9 | ✅ `fea11d9`, aktör semantiği `b850ad1` |
| **M1** | SSE-C (client-supplied key, AES-256-GCM/chunk) | 8 | ✅ `565796b` |
| **Sonuç** | | **23** | **110 supported / 2 partial / 4 unsupported** |
| **D — imkânsız** | Torrent, CreateSession, ListDirectoryBuckets, WriteGetObjectResponse | 4 | ⛔ kalıcı olarak unsupported |

> **Kalan iki partial:** `GetBucketRequestPayment` ve
> `GetBucketAccelerateConfiguration`. Her ikisi de tek gerçek state'i
> (BucketOwner / Suspended) döndürür; karşı state requester-pays billing
> veya bir edge network gerektirdiği için yazma tarafı 501 verir. Bunları
> "supported" saymak, var olmayan bir faturalama/edge altyapısını varmış
> gibi göstermek olurdu.

> **Neden bu 4'ü "destekliyoruz" demiyoruz:** `GetObjectTorrent` bir
> BitTorrent swarm/seeder gerektirir (üretilen .torrent'i seed edememek
> kullanıcıyı yanıltır), `CreateSession`/`ListDirectoryBuckets` S3 Express
> One Zone directory bucket'larına bağlıdır (öyle bir depolama yok),
> `WriteGetObjectResponse` S3 Object Lambda'dır (Lambda çalıştırma ortamı
> yok). Dördü de gerçek bir backing olmadan uydurulursa "supported"
> etiketi yalan olur. TeleDrive'ın kullanım profili (self-host yedekleme)
> bu çağrıları hiç üretmez.

## 0. Sınıflandırma

| Sınıf | Anlam | Adet |
|---|---|---|
| **A — Gerçek backing var** | Mevcut SQL/engine üzerine gerçek semantik kurulabilir | 44 |
| **B — Sadece var olan state** | Tek gerçek değer kabul edilir, diğeri dürüstçe 501 | 4 |
| **C — Sadece SSE ile açılır** | Partial'lar encryption gelince kapanır | 4 |
| **D — İmkânsız** | Altyapı yok, uydurmak yalan olur | 4 |

---

## 1. FAZ L — Policy engine (en yüksek değer)

**Kapatır:** `PutBucketPolicy`, `DeleteBucketPolicy`, `GetBucketPolicy` (partial),
`GetBucketAbac`, `PutBucketAbac`, `PutBucketOwnershipControls`,
`DeleteBucketOwnershipControls`, `DeletePublicAccessBlock` → **8 operasyon**

### L1 — `teledrive/s3/policy.py` (yeni)

Gerçek IAM-style JSON policy engine. Şu an "policy engine yok" diye reddediyoruz;
aslında elimizde ihtiyacın tamamı var: credential'lar (principal), ACL grant'ları
(resource), ve tek bir yetki kapısı (`_acl_allows`).

Desteklenen belge:

```json
{"Version": "2012-10-17",
 "Statement": [
   {"Sid": "deny-delete", "Effect": "Deny",
    "Principal": {"CanonicalUser": ["TDB67BD1ABE1D21E7768F0A23"]},
    "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
    "Resource": ["arn:aws:s3:::photos/*"],
    "Condition": {"StringLike": {"s3:prefix": ["private/*"]}}}
 ]}
```

**Sıkı kurallar (fail-closed):**
- `Principal`: yalnız `CanonicalUser` listesi, her ID aktif bir access key olmalı.
  `"*"`, `AWS`, `Service`, `Federated` → **501** (private-only çizgisi).
- `Action`: `s3:*` glob (`*` ve `?`), bilinmeyen action adı → 400.
- `Resource`: `arn:aws:s3:::bucket` ve `bucket/key` glob; başka partition → 400.
- `Effect`: `Allow` | `Deny`. **Deny her zaman kazanır.**
- `Condition`: yalnız gerçekten değerlendirebildiğimiz operatörler:
  `StringEquals`, `StringLike`, `StringNotEquals`, `IpAddress`, `NotIpAddress`,
  `Bool`, `NumericLessThan/Equals/GreaterThan`. Anahtarlar:
  `s3:prefix`, `s3:max-keys`, `s3:delimiter`, `aws:SourceIp`,
  `s3:ExistingObjectTag/<key>`, `aws:PrincipalTag/<key>`, `s3:x-amz-acl`.
  Bilinmeyen operatör/anahtar → **400** (sessizce yok saymak yetki genişletir).
- Belge boyutu ≤ 20 KiB (AWS ile aynı), statement ≤ 50, derinlik sınırlı.

### L2 — Tek karar noktası

`web/s3.py::_authorize_resource(catalog, access_key, action, bucket, key)`:

```
1. credential scope check (SigV4 — zaten var)
2. bucket policy: explicit Deny?      → reddet
3. bucket policy: explicit Allow?     → ACL katmanını atla (AWS semantiği)
4. kanıt yoksa: ACL intersection gate (Phase D) → mevcut davranış
```

Bu, mevcut `_acl_allows`'un yerini alır; ACL ve policy aynı fonksiyonda
birleşir. Tek karar noktası = tek test edilecek yer.

### L3 — Değerlendirme maliyeti

Policy her istekte parse edilmez: bucket başına derlenmiş AST + LRU cache,
`updated_at` ile invalidate. 20 KiB sınırı + 50 statement ile üst sınır sabit.

### L4 — ABAC

`GetBucketAbac`/`PutBucketAbac` bu motorun üstüne oturur: ABAC sadece
`aws:PrincipalTag/*` ve `s3:ExistingObjectTag/*` condition'larının bucket
seviyesinde zorunlu kılınmasıdır. Credential tag'leri `api_credentials` ve
`s3_credentials` tablolarına `tags` JSON kolonu olarak eklenir.

### L5 — Ownership controls (artık gerçek)

| Değer | Gerçek semantik |
|---|---|
| `BucketOwnerEnforced` (varsayılan) | Object ACL'leri erişim kararında **yok sayılır**; sadece owner + policy |
| `ObjectWriter` | Object ACL grant'ları **uygulanır** (bugünkü Phase D davranışı) |
| `BucketOwnerPreferred` | ObjectWriter + `bucket-owner-full-control` canned ACL ile yüklenen nesnede owner grant otomatik |

`Delete` → `BucketOwnerEnforced`'e döner. Artık sabit değil, davranışı değiştiren
gerçek bir ayar.

### L6 — DeletePublicAccessBlock

PAB satırını siler → varsayılan all-true'ya döner (en kısıtlayıcı). Kaybetme riski
sıfır. Tek uyarı: `BlockPublicAcls` kapanmışsa ve policy'de public principal
yoksa (ki olamaz, 501), sonuç yine güvenli.

**Efor:** L (1 hafta). **Test:** yeni `tests/s3/test_s3_policy_engine.py` +
`tests/s3/test_s3_abac.py`, ~40 senaryo (deny-overrides, glob, condition,
principal doğrulama, cache invalidation, ACL ile birlikte).

---

## 2. FAZ M — Encryption (SSE)

**Kapatır:** `PutBucketEncryption`, `DeleteBucketEncryption`, `GetBucketEncryption`
(partial), `UpdateObjectEncryption`, `PutObject`, `GetObject`, `HeadObject`,
`CreateMultipartUpload` (partial'lar) → **8 operasyon**

### M1 — SSE-C (gerçek, öncelikli)

Client her istekte anahtarı verir; biz saklamayız. Chunk'lar AES-256-GCM ile
şifrelenir, nonce chunk başına rastgele, AAD = object_id + ordinal.

- Header'lar: `x-amz-server-side-encryption-customer-{algorithm,key,key-md5}`
- Yanlış anahtar → `InvalidRequest` (GCM tag doğrulaması ile, oracle yok)
- **Dedup doğal olarak kapanır** (aynı plaintext farklı ciphertext) — AWS'de de
  böyle. Content search o nesneler için kapanır (dokümante edilir).
- `UpdateObjectEncryption` = eski anahtarla aç, yeni anahtarla şifrele (gerçek
  rotasyon, tek transaction + chunk re-upload).

### M2 — SSE-S3 (gerçek, opsiyonel mod)

`storage.encryption = none | envelope`. Envelope açıkken:
- Master key (`/config/s3.key`) → per-object data key wrap (AES-KW)
- Chunk'lar data key ile şifreli, checksum ciphertext üzerinde
- **Dedup / replication / content-search kendini kapatır** ve bunu `/api/v1/admin/storage/health`
  üzerinden raporlar. Bu bir gerileme değil, bilinçli takas: hangi ikisini
  istediğini owner seçer.
- `GetBucketEncryption` gerçek config'i döner.

### M3 — SSE-KMS

KMS yok. `x-amz-server-side-encryption: aws:kms` → **501** (dürüst).
`AES256` → SSE-S3. `aws:kms` + key-id → 501 "no KMS backing".
Bucket config'te KMS kuralı → 501.

**Efor:** L (1 hafta, M1) + M (3 gün, M2). **Test:** `tests/s3/test_s3_sse_c.py`,
`test_s3_envelope.py`; ayrıca AES-GCM vektörleri, yanlış anahtar reddi,
rotasyon, range read (parça bazlı çözme), multipart.

---

## 3. FAZ N — Raporlama konfigürasyonları (16 operasyon, çoğu CRUD + gerçek üretim)

AWS'nin "configuration" ailesi: hepsi **config CRUD + zamanlanmış çıktı**.
Config CRUD tek bir generic katmanla yapılır; çıktı üretimi zaten var olan
storage engine + Phase F outbox ile gerçek.

### N1 — Generic config store

`teledrive/s3/report_configs.py`: tek tablo `storage_report_configs`
(`bucket`, `kind` ∈ {analytics, inventory, metrics, tiering}, `config_id`,
`document` JSON, `created/updated`). Strict XML parse, id başına 1 kayıt,
`List*` sıralı döner. **12 operasyon** buradan gelir.

### N2 — Inventory (gerçek CSV manifest)

`GetBucketInventoryConfiguration` vb. → config'teki `Destination` bucket'ına
**gerçek CSV manifest** yazılır (AWS inventory CSV şeması: Bucket, Key,
VersionId, IsLatest, Size, LastModifiedDate, ETag, StorageClass).
Günlük/haftalık scheduler (`lifecycle_scheduler_loop` yanına).
`IncludedObjectVersions=All` gerçekten desteklenir (version journal'ımız var).
ORC/Parquet → 501 (CSV + gzip gerçek olan).

### N3 — Analytics (gerçek rapor, format sapması dokümante)

Aynı iskelet; çıktı JSON Lines (AWS Parquet). Sapma `docs/S3_SPECS.md`'de açıkça
yazılır. Filter (prefix/tag) gerçekten uygulanır.

### N4 — Metrics (CloudWatch yok → kendi gerçek kanalı)

CloudWatch'a gönderemeyiz. Gerçek backing: metrikler `/api/v1/admin/storage/metrics/{config_id}`
altında **gerçekten hesaplanır** (bucket boyutu, nesne sayısı, istek sayacı —
istek sayacı HTTP middleware'inden gelir) ve istenirse Phase F webhook outbox'ı
ile hedefe itilir. `Destination` alanı bu kanalı tanımlar. Dokümante: "not CloudWatch".

### N5 — Intelligent-Tiering (gerçek erişim takibi)

Bugün erişim sayacı yok — bu fazla eklenir:
- `storage_objects.access_count`, `last_accessed_ns` (defansif ALTER)
- Her GetObject/HeadObject'ta atomik artırım (tek UPDATE, index'li)
- Config'teki `Days`/`AccessTier` eşiklerine göre nesne **gerçekten** bir
  `storage_class` etiketi alır (`STANDARD` → `INFREQUENT_ACCESS` → `ARCHIVE`)
- `ARCHIVE` etiketi lifecycle'a girer: chunk'lar replica'da tutulur, primary
  Telegram'dan GC ile düşer → **RestoreObject artık gerçek bir iş yapar** (aşağıda)

**Efor:** N1 2 gün, N2/N3 3 gün, N4 2 gün, N5 4 gün. **Test:** her kind için
CRUD + üretim testi, scheduler idempotency, erişim sayacı yarış testi.

---

## 4. FAZ O — Kolay gerçek kazanımlar

### O1 — RestoreObject (gerçek, N5'e bağlı)

N5 ile `ARCHIVE` sınıfı gerçek olduğunda:
- `ARCHIVE` nesne → `403 InvalidObjectState` (AWS ile aynı)
- `ARCHIVE` + `RestoreObject` → replica'dan chunk'lar geri getirilir, `restore_until_ns`
  set edilir, `202 Accepted`; süre dolunca tekrar arşive
- N5 olmadan: her zaman `403 InvalidObjectState` — **yine de %100 AWS-conformant**
  (nesne zaten erişilebilir bir sınıfta). Yani bu operasyon N5'ten bağımsız da
  doğru davranır.

### O2 — Object annotations (4 op)

`storage_object_annotations` (`object_id`, `name`, `value`). Tag'den farkı: isim
serbest metin, 50 adet, 1 KiB değer. `ListObjectAnnotations` sayfalama ile.
**Efor:** S (yarım gün).

### O3 — Bucket metadata configuration (9 op)

Gerçek metadata journal: `storage_metadata_journal` (nesne mutasyonları: create/
delete/tag/ACL değişimi, zaman, aktör). Config CRUD + `Get` bu journal'ı
sayfalar. AWS'nin "metadata table"ı (AWS-managed Iceberg) taklit edilmez;
bizim tablomuz gerçek ve sorgulanabilir. **Efor:** M (2 gün).

### O4 — RenameObject (gerçek atomik rename)

Catalog'umuz tek transaction'da head taşıması yapabildiği için rename = 
`copy + delete` tek transaction'da (chunk'lar yer değiştirmez, sadece key_hash).
AWS bunu yalnız directory bucket'larda sunar; biz standart bucket'ta sunarız ve
bunu **dokümante edilmiş bir süperset** olarak işaretleriz. **Efor:** S (1 gün).

### O5 — SelectObjectContent (gerçek sorgu)

Chunk'ları indir → CSV/JSON parse → S3 Select SQL alt kümesi
(`SELECT`/`FROM`/`WHERE`/`LIMIT`, karşılaştırma + `AND`/`OR`) → event stream
(`Records`, `Stats`, `End`). Bounded: ≤ 256 MiB tarama, ≤ 1 MiB/olay.
Parquet → 501. **Efor:** M (3 gün).

### O6 — RequestPayment / Accelerate (B sınıfı)

| Op | Gerçek state | Kabul | Ret |
|---|---|---|---|
| `PutBucketRequestPayment` | `Payer=BucketOwner` (billing yok) | `BucketOwner` | `Requester` → 501 |
| `PutBucketAccelerateConfiguration` | `Status=Suspended` (edge yok) | `Suspended` | `Enabled` → 501 |

Böylece operasyon "destekleniyor" olur çünkü **var olan tek state'i doğru
yönetir**; olmayan bir şeyi kabul etmez. **Efor:** S (2 saat).

---

## 5. Kalıcı olarak imkânsız (4)

| Operasyon | Neden |
|---|---|
| `GetObjectTorrent` | BitTorrent swarm/seeder altyapısı yok; .torrent dosyası üretmek ama seed edememek yalan olur |
| `CreateSession` | S3 Express One Zone session token'ı; directory bucket yok |
| `ListDirectoryBuckets` | Directory bucket diye bir şey yok |
| `WriteGetObjectResponse` | S3 Object Lambda; Lambda çalıştırma ortamı yok |

Bunlar `unsupported` kalır ve `docs/S3_SPECS.md` 3.3'te "no honest backing"
gerekçesiyle listelenir. **Dördü de gerçek bir müşteri ihtiyacı değil** —
TeleDrive'ın kullanım profili (kişisel/self-host yedekleme) bunları hiç çağırmaz.

---

## 6. Sıralama ve bağımlılık

> Bu bölüm planlama kaydıdır; fazların tamamı `f341691`, `fea11d9` ve
> `565796b` ile sevk edildi. Güncel envanter 110 supported / 2 partial /
> 4 unsupported.

```
FAZ L (policy + ownership + PAB)     8 op   ~6 gün   bağımsız
FAZ O2/O6 (annotations, R/P, accel)  8 op   ~2 gün   bağımsız
FAZ M (SSE-C → SSE-S3)               8 op   ~8 gün   bağımsız
FAZ N1+N2+N3 (config + raporlar)    12 op   ~5 gün   bağımsız
FAZ N5 (access tracking + tiering)   4 op   ~4 gün   N1 sonrası
FAZ O1 (RestoreObject)               1 op   ~1 gün   N5 sonrası (yoksa da doğru)
FAZ O3 (metadata journal)            9 op   ~2 gün   bağımsız
FAZ O4/O5 (rename, select)           2 op   ~4 gün   bağımsız
FAZ N4 (metrics kanalı)              4 op   ~2 gün   N1 sonrası
```

Toplam ~34 gün tek geliştirici; 3 paralel ajanla ~12 gün takvim.

**Önerilen sıra (değer/efor):** O2+O6 (1 gün, 6 op) → L (6 gün, 8 op) →
N1+N2+N3 (5 gün, 12 op) → M (8 gün, 8 op) → O3 (2 gün, 8 op) → N5+O1 (5 gün, 5 op)
→ O4+O5+N4 (8 gün, 6 op).

---

## 7. Her fazın zorunlu ritüeli

1. Yeni tablo → `MetaData` + defansif ALTER (SQLite `PRAGMA` / `information_schema`
   **şema filtreli**), `BucketCatalog.__init__` veya store ctor'da `create_all`
   (**asla** mutation hot path'inde — Phase J'de SQLite deadlock yaşandı).
2. Config CRUD → strict, bounded (16–20 KiB) defused XML; bilinmeyen alan 400,
   desteklenmeyen semantik 501.
3. Permission: `teledrive/s3/credentials.py`'ye `s3:Put*/Delete*` eklenir.
4. Route guard: `teledrive/s3/route_guard.py`'de method matrisi.
5. Adversarial testler: `tests/s3/test_s3_route_guard.py` (CRUD'a düşmüyor),
   `test_s3_compat_reads.py`, `test_s3_unsupported_sweep.py`.
6. Envanter senkronu: manifest → `S3_SPECS.md` 3.1/3.3 → totals satırı →
   route_guard Counter → meta totals → yeni test modülünü CI'a kaydet.
7. Canlı doğrulama: PostgreSQL + MySQL (temiz VE legacy şema) + boto3 round-trip
   + TLS.
8. Her faz sonunda CI 6/6 yeşil, sonra deploy.

---

## 8. Dürüstlük sözleşmesi (değişmez)

Bu plan boyunca şu üç şey **asla** yapılmaz:

1. **Uydurma kabul.** Desteklenmeyen bir AWS özelliğini 200 ile geçiştirmek
   (ör. SSE-KMS'i sessizce AES256'ya düşürmek) yasak; 501 döner.
2. **Sessiz yetki genişletme.** Bilinmeyen policy condition'ı, bilinmeyen ACL
   grantee'si, eksik zorunlu alan → reddet. Varsayılan her zaman "izin verme".
3. **Sahte rapor.** Üretilmeyen bir raporu "delivered" saymak yasak; üretim
   gerçekten yapılır veya operasyon 501 kalır.

Bu sözleşme sayesinde "supported" etiketi, "test edilmiş ve gerçekten çalışıyor"
anlamına gelir — S3 uyumluluğu iddiası değil, **ölçülmüş davranış** iddiası.
