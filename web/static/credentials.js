// S3 credential console: permission catalogue, presets and risk metadata.
//
// The S3 scope set is static in the server (teledrive/s3/credentials.py),
// and there is no public catalogue endpoint for it, so the grouping lives
// here. tests/web/test_credentials_ui.py pins this catalogue against the
// server's PERMISSIONS set: a scope that is enforceable but not shown here
// would be ungrantable from the UI, which is the failure this file exists
// to prevent.
//
// Secret handling rule: an access key and secret live only in the Alpine
// component that received them from the API and are rendered into this
// page. They are never written to browser storage, never put in the URL
// and never sent anywhere except the API that issued them.
(function (global) {
  'use strict';

  // --- Permission families ------------------------------------------------
  // One entry per resource family. `description` is shown under the group
  // title so an operator can decide without reading 88 checkbox labels.
  var GROUPS = [
    {
      id: 'bucket-core',
      label: 'Buckets & listing',
      description: 'Enumerate buckets, create and delete bucket names, list object keys and read the bucket region.',
      perms: [
        's3:ListAllMyBuckets', 's3:CreateBucket', 's3:DeleteBucket',
        's3:ListBucket', 's3:ListBucketVersions', 's3:GetBucketLocation'
      ]
    },
    {
      id: 'directory-buckets',
      label: 'S3 Express (directory buckets)',
      description: 'The S3 Express surface. TeleDrive has no directory buckets, so the listing is always empty and no session can ever be issued — granting these only removes an AccessDenied from clients that probe them.',
      perms: [
        's3:ListDirectoryBuckets', 's3:CreateSession'
      ]
    },
    {
      id: 'objects',
      label: 'Objects',
      description: 'Read, write, copy-rename, restore and Select the object payload itself.',
      perms: [
        's3:GetObject', 's3:GetObjectAttributes', 's3:PutObject',
        's3:DeleteObject', 's3:RenameObject', 's3:SelectObjectContent',
        's3:RestoreObject'
      ]
    },
    {
      id: 'tagging',
      label: 'Tagging',
      description: 'Object and bucket tag sets. Tags drive lifecycle filters and replication rules.',
      perms: [
        's3:GetObjectTagging', 's3:PutObjectTagging', 's3:DeleteObjectTagging',
        's3:GetBucketTagging', 's3:PutBucketTagging', 's3:DeleteBucketTagging'
      ]
    },
    {
      id: 'annotations',
      label: 'Annotations',
      description: 'The metadata annotation store, kept separate from object tags.',
      perms: [
        's3:GetObjectAnnotation', 's3:PutObjectAnnotation',
        's3:DeleteObjectAnnotation', 's3:ListObjectAnnotations'
      ]
    },
    {
      id: 'acl',
      label: 'ACL',
      description: 'Bucket and object grants to other S3 credentials. Grants intersect with scopes.',
      perms: [
        's3:GetBucketAcl', 's3:PutBucketAcl', 's3:GetObjectAcl', 's3:PutObjectAcl'
      ]
    },
    {
      id: 'policy',
      label: 'Policy & ownership',
      description: 'The bucket policy document, its public-status answer, ownership controls and ABAC attributes.',
      perms: [
        's3:GetBucketPolicy', 's3:PutBucketPolicy', 's3:DeleteBucketPolicy',
        's3:GetBucketPolicyStatus',
        's3:GetOwnershipControls', 's3:PutBucketOwnershipControls',
        's3:DeleteBucketOwnershipControls',
        's3:GetBucketAbac', 's3:PutBucketAbac'
      ]
    },
    {
      id: 'pab',
      label: 'Public access block',
      description: 'The four bucket-level flags that gate public access, and the honest IsPublic scan.',
      perms: ['s3:GetBucketPublicAccessBlock', 's3:PutBucketPublicAccessBlock']
    },
    {
      id: 'object-lock',
      label: 'Object lock & retention',
      description: 'WORM configuration, per-version retention and legal hold. Enforcement covers every delete path.',
      perms: [
        's3:GetBucketObjectLockConfiguration', 's3:PutBucketObjectLockConfiguration',
        's3:GetObjectRetention', 's3:PutObjectRetention',
        's3:GetObjectLegalHold', 's3:PutObjectLegalHold'
      ]
    },
    {
      id: 'versioning',
      label: 'Versioning & payer',
      description: 'Enabled/Suspended versioning state and the single real request-payer state.',
      perms: [
        's3:GetBucketVersioning', 's3:PutBucketVersioning',
        's3:GetBucketRequestPayment', 's3:PutBucketRequestPayment'
      ]
    },
    {
      id: 'lifecycle',
      label: 'Lifecycle',
      description: 'Expiration and abort-incomplete-multipart rules evaluated hourly.',
      perms: ['s3:GetLifecycleConfiguration', 's3:PutLifecycleConfiguration']
    },
    {
      id: 'cors',
      label: 'CORS',
      description: 'Browser preflight grammar: origins, methods, headers and max age.',
      perms: ['s3:GetBucketCORS', 's3:PutBucketCORS']
    },
    {
      id: 'website',
      label: 'Website',
      description: 'Index and error documents served at /site/{bucket}/ once an admin enables public read.',
      perms: ['s3:GetBucketWebsite', 's3:PutBucketWebsite', 's3:DeleteBucketWebsite']
    },
    {
      id: 'notifications',
      label: 'Event notifications',
      description: 'Webhook targets for bucket events, delivered through a transactional outbox.',
      perms: ['s3:GetBucketNotification', 's3:PutBucketNotification']
    },
    {
      id: 'logging',
      label: 'Access logging',
      description: 'The stored access-log target for the bucket. Delivery into that bucket is not claimed.',
      perms: ['s3:GetBucketLogging', 's3:PutBucketLogging']
    },
    {
      id: 'replication',
      label: 'Replication',
      description: 'Per-object replication to another configured credential set.',
      perms: [
        's3:GetBucketReplication', 's3:PutBucketReplication',
        's3:DeleteBucketReplication'
      ]
    },
    {
      id: 'encryption',
      label: 'Encryption & SSE-C',
      description: 'Bucket encryption state and client-supplied SSE-C keys. There is no SSE-S3/KMS scope: no server key exists to grant.',
      perms: [
        's3:GetBucketEncryption', 's3:PutBucketEncryption',
        's3:DeleteBucketEncryption', 's3:GetEncryptionConfiguration',
        's3:PutObjectEncryption'
      ]
    },
    {
      id: 'metadata-config',
      label: 'Metadata configuration',
      description: 'The S3 Metadata journal, inventory and annotation tables, including their retention windows.',
      perms: [
        's3:CreateBucketMetadataTableConfiguration',
        's3:GetBucketMetadataTableConfiguration',
        's3:DeleteBucketMetadataTableConfiguration',
        's3:UpdateBucketMetadataJournalTableConfiguration',
        's3:UpdateBucketMetadataInventoryTableConfiguration',
        's3:UpdateBucketMetadataAnnotationTableConfiguration'
      ]
    },
    {
      id: 'tiering',
      label: 'Intelligent-Tiering',
      description: 'Access-tiering configuration and the catalog gate used by RestoreObject.',
      perms: [
        's3:GetBucketIntelligentTieringConfiguration',
        's3:PutBucketIntelligentTieringConfiguration',
        's3:DeleteBucketIntelligentTieringConfiguration',
        's3:ListBucketIntelligentTieringConfigurations'
      ]
    },
    {
      id: 'reports',
      label: 'Storage reports',
      description: 'Analytics, inventory and metrics configuration CRUD. Reads are separately grantable.',
      perms: [
        's3:GetBucketAnalyticsConfiguration', 's3:PutBucketAnalyticsConfiguration',
        's3:DeleteBucketAnalyticsConfiguration',
        's3:GetBucketInventoryConfiguration', 's3:PutBucketInventoryConfiguration',
        's3:DeleteBucketInventoryConfiguration',
        's3:GetBucketMetricsConfiguration', 's3:PutBucketMetricsConfiguration',
        's3:DeleteBucketMetricsConfiguration'
      ]
    },
    {
      id: 'accelerate',
      label: 'Transfer acceleration',
      description: 'The transfer-acceleration state, stored and reported honestly.',
      perms: [
        's3:GetAccelerateConfiguration', 's3:PutBucketAccelerateConfiguration'
      ]
    }
  ];

  var ALL = [];
  GROUPS.forEach(function (g) { g.perms.forEach(function (p) { ALL.push(p); }); });

  var BY_SCOPE = {};
  GROUPS.forEach(function (g) {
    g.perms.forEach(function (p) { BY_SCOPE[p] = g; });
  });

  // --- Risk metadata ------------------------------------------------------
  // level 'destructive': the request removes or moves data.
  // level 'governance': the request changes who can reach data, how long it
  // must be kept, or whether it is public. Neither level blocks the grant;
  // the operator is told what the scope can do and decides.
  var GOVERNANCE_RISKS = {
    's3:PutBucketPolicy': 'Replaces the whole bucket policy in one request. A wrong document can lock every client out of the bucket.',
    's3:DeleteBucketPolicy': 'Removes the bucket policy. Every principal that relied on it loses access immediately.',
    's3:PutBucketObjectLockConfiguration': 'Object Lock cannot be disabled once enabled, and COMPLIANCE retention can never be shortened. This is irreversible.',
    's3:PutObjectRetention': 'Pins a version as immutable until the retain-until date. COMPLIANCE retention cannot be shortened or removed.',
    's3:PutObjectLegalHold': 'Blocks deletion of the version while the hold is ON.',
    's3:PutBucketAcl': 'Changes who can read or write the bucket. ACL grants intersect with scopes, so a wrong grant silently hides data.',
    's3:PutObjectAcl': 'Changes who can reach this object. The grant applies to every version of the object.',
    's3:PutObjectEncryption': 'Binds the object to a client-supplied SSE-C key. Lose that key and the payload is unreadable: TeleDrive cannot recover it.',
    's3:PutBucketPublicAccessBlock': 'Changes the public-access gate for the whole bucket, in either direction.',
    's3:PutBucketOwnershipControls': 'Changes the ownership model applied to every object in the bucket.',
    's3:PutBucketAbac': 'Replaces the attribute-based rules evaluated on every signed request against this bucket.',
    's3:PutBucketVersioning': 'Suspending versioning makes the next write overwrite the current version instead of adding one.',
    's3:PutLifecycleConfiguration': 'Expired objects are deleted by the next hourly evaluation. An off-by-one in Days removes data early.',
    's3:PutBucketReplication': 'Starts copying new objects to another configured credential set. Bad rules replicate deletions too.',
    's3:DeleteBucketReplication': 'Stops replication. Objects written after this have no off-site copy.',
    's3:PutBucketWebsite': 'Publishes the stored documents at /site/{bucket}/ as soon as an admin enables public read.',
    's3:DeleteBucketWebsite': 'Removes the site document and closes the public gate for this bucket.',
    's3:PutBucketNotification': 'Redirects bucket event delivery. A wrong target silently starves downstream consumers.',
    's3:PutBucketLogging': 'Replaces the access-log target for the bucket.',
    's3:PutBucketRequestPayment': 'Changes the stored payer state clients read before they upload.',
    's3:PutBucketAccelerateConfiguration': 'Changes the acceleration state clients read before they transfer.',
    's3:UpdateBucketMetadataJournalTableConfiguration': 'Changes the metadata journal retention window. Shortening it discards journal rows that cannot be recreated.',
    's3:UpdateBucketMetadataInventoryTableConfiguration': 'Changes the inventory table retention window. Shortening it discards inventory rows that cannot be recreated.',
    's3:UpdateBucketMetadataAnnotationTableConfiguration': 'Changes the annotation table retention window. Shortening it discards annotation rows that cannot be recreated.',
    's3:RenameObject': 'Moves the object: the source key disappears in the same request. There is no undo, only a copy back.'
  };

  var DESTRUCTIVE_SUFFIX = 'Destroys catalog state. Recovery depends on versioning and the grace-fenced GC policy; the S3 API itself has no undelete.';

  function riskFor(scope) {
    if (!scope) return null;
    if (Object.prototype.hasOwnProperty.call(GOVERNANCE_RISKS, scope)) {
      return { level: 'amber', label: 'governance', message: GOVERNANCE_RISKS[scope] };
    }
    if (scope.indexOf('s3:Delete') === 0) {
      return { level: 'red', label: 'destructive', message: DESTRUCTIVE_SUFFIX };
    }
    return null;
  }

  var DANGEROUS = ALL.filter(function (p) { return !!riskFor(p); });

  // --- Presets ------------------------------------------------------------
  // Each preset is a starting point, never a mode: applying it replaces the
  // current selection and the operator can keep editing every checkbox.
  var PRESETS = [
    {
      id: 'read-only',
      label: 'Read-only',
      consequence: 'List buckets and objects, download payloads and read configuration. Cannot write, delete or change any setting.',
      perms: [
        's3:ListAllMyBuckets', 's3:ListBucket', 's3:ListBucketVersions',
        's3:GetBucketLocation', 's3:GetObject', 's3:GetObjectAttributes',
        's3:GetObjectTagging', 's3:GetObjectAnnotation', 's3:ListObjectAnnotations',
        's3:GetObjectAcl', 's3:GetBucketAcl', 's3:GetBucketTagging',
        's3:GetBucketVersioning', 's3:GetBucketCORS', 's3:GetBucketWebsite',
        's3:GetLifecycleConfiguration', 's3:GetBucketPolicyStatus',
        's3:GetBucketPublicAccessBlock', 's3:GetBucketObjectLockConfiguration',
        's3:GetBucketEncryption', 's3:GetEncryptionConfiguration',
        's3:GetBucketReplication', 's3:GetBucketNotification', 's3:GetBucketLogging',
        's3:GetBucketRequestPayment', 's3:GetAccelerateConfiguration',
        's3:GetOwnershipControls', 's3:GetBucketPolicy', 's3:GetBucketAbac',
        's3:GetObjectRetention', 's3:GetObjectLegalHold',
        's3:GetBucketAnalyticsConfiguration', 's3:GetBucketInventoryConfiguration',
        's3:GetBucketMetricsConfiguration',
        's3:GetBucketIntelligentTieringConfiguration',
        's3:ListBucketIntelligentTieringConfigurations',
        's3:GetBucketMetadataTableConfiguration'
      ]
    },
    {
      id: 'backup',
      label: 'Backup client',
      consequence: 'Write new objects and list what already exists so an incremental backup can skip. Can overwrite a key, but cannot delete or change bucket settings.',
      perms: [
        's3:ListAllMyBuckets', 's3:ListBucket', 's3:GetBucketLocation',
        's3:GetObject', 's3:GetObjectAttributes', 's3:PutObject',
        's3:GetObjectTagging', 's3:PutObjectTagging'
      ]
    },
    {
      id: 'sync',
      label: 'Sync client',
      consequence: 'Two-way sync: read, write, overwrite, delete and tag objects. Cannot change bucket-level configuration.',
      perms: [
        's3:ListAllMyBuckets', 's3:ListBucket', 's3:ListBucketVersions',
        's3:GetBucketLocation', 's3:GetObject', 's3:GetObjectAttributes',
        's3:PutObject', 's3:DeleteObject', 's3:RenameObject',
        's3:GetObjectTagging', 's3:PutObjectTagging', 's3:DeleteObjectTagging',
        's3:GetObjectAnnotation', 's3:PutObjectAnnotation',
        's3:DeleteObjectAnnotation', 's3:ListObjectAnnotations'
      ]
    },
    {
      id: 'bucket-admin',
      label: 'Bucket administrator',
      consequence: 'Operate the bucket: objects, tags, versioning, lifecycle, CORS, website, reports. Cannot delete data or change policy, ACL, object-lock or public-access governance.',
      perms: ALL.filter(function (p) {
        if (p.indexOf('s3:Delete') === 0) return false;
        if (p === 's3:CreateBucket') return false;
        if (p === 's3:PutBucketPolicy' || p === 's3:DeleteBucketPolicy') return false;
        if (p === 's3:PutBucketAcl' || p === 's3:PutObjectAcl') return false;
        if (p === 's3:PutBucketOwnershipControls' || p === 's3:DeleteBucketOwnershipControls') return false;
        if (p === 's3:PutBucketAbac') return false;
        if (p === 's3:PutBucketPublicAccessBlock') return false;
        if (p.indexOf('s3:PutBucketObjectLock') === 0) return false;
        if (p.indexOf('s3:PutObjectRetention') === 0 || p.indexOf('s3:PutObjectLegalHold') === 0) return false;
        if (p === 's3:PutObjectEncryption') return false;
        if (p.indexOf('s3:UpdateBucketMetadata') === 0) return false;
        if (p === 's3:RenameObject') return false;
        return true;
      })
    },
    {
      id: 'full',
      label: 'Full access',
      consequence: 'Every S3 action, including deletion, policy, ACL, object-lock and metadata-retention changes. Equivalent to handing over the bucket.',
      perms: ALL.slice()
    }
  ];

  var PRESET_BY_ID = {};
  PRESETS.forEach(function (p) { PRESET_BY_ID[p.id] = p; });

  // --- Pure helpers -------------------------------------------------------

  function selectedCount(perms) { return (perms || []).length; }

  function groupSelection(group, perms) {
    perms = perms || [];
    var hits = group.perms.filter(function (p) { return perms.indexOf(p) >= 0; });
    return {
      selected: hits.length,
      total: group.perms.length,
      all: hits.length === group.perms.length,
      some: hits.length > 0 && hits.length < group.perms.length
    };
  }

  function presetGroups(presetId, perms) {
    var preset = PRESET_BY_ID[presetId];
    if (!preset) return [];
    perms = perms || [];
    return GROUPS.filter(function (g) {
      return g.perms.some(function (p) {
        return preset.perms.indexOf(p) >= 0 && perms.indexOf(p) >= 0;
      });
    }).map(function (g) { return g.label; });
  }

  function risksIn(perms) {
    return (perms || []).map(function (scope) {
      var risk = riskFor(scope);
      return risk ? { scope: scope, level: risk.level, label: risk.label, message: risk.message } : null;
    }).filter(Boolean);
  }

  function relative(ts, nowSeconds) {
    if (!ts) return 'never';
    var now = nowSeconds == null ? Math.floor(Date.now() / 1000) : nowSeconds;
    var s = now - ts;
    var future = s < 0;
    s = Math.abs(s);
    var text;
    if (s < 60) text = 'moments';
    else if (s < 3600) text = Math.floor(s / 60) + ' min';
    else if (s < 86400) text = Math.floor(s / 3600) + ' h';
    else if (s < 30 * 86400) text = Math.floor(s / 86400) + ' d';
    else if (s < 365 * 86400) text = Math.floor(s / (30 * 86400)) + ' mo';
    else text = Math.floor(s / (365 * 86400)) + ' y';
    if (text === 'moments') return future ? 'in moments' : 'moments ago';
    return future ? 'in ' + text : text + ' ago';
  }

  // Expiry state drives both the badge text and the inline sentence, so a
  // user who cannot distinguish amber from grey still reads "expires soon".
  function expiryState(ts, nowSeconds) {
    if (!ts) return 'never';
    var now = nowSeconds == null ? Math.floor(Date.now() / 1000) : nowSeconds;
    if (ts <= now) return 'expired';
    if (ts - now <= 7 * 86400) return 'soon';
    return 'active';
  }

  function describeCredential(key, nowSeconds) {
    var now = nowSeconds == null ? Math.floor(Date.now() / 1000) : nowSeconds;
    if (key.revoked) {
      return { state: 'revoked', badge: 'badge-gray', label: 'revoked',
               sentence: 'Revoked — clients signing with this key are rejected.' };
    }
    var state = expiryState(key.expires_at, now);
    if (state === 'expired') {
      return { state: 'expired', badge: 'badge-amber', label: 'expired',
               sentence: 'Expired — signing with this key is rejected.' };
    }
    if (state === 'soon') {
      return { state: 'soon', badge: 'badge-amber', label: 'expires soon',
               sentence: 'Expires soon — replace the client secret before this date.' };
    }
    return { state: state, badge: 'badge-green', label: 'active', sentence: 'Active.' };
  }

  // Groups a credential's stored scopes, for the list column. Unknown
  // scopes are named explicitly instead of being hidden.
  function groupLabels(perms) {
    var labels = [];
    var unknown = [];
    (perms || []).forEach(function (p) {
      var g = BY_SCOPE[p];
      if (!g) { unknown.push(p); return; }
      if (labels.indexOf(g.label) < 0) labels.push(g.label);
    });
    if (unknown.length) labels.push(unknown.length + ' ungrouped');
    return labels;
  }

  // --- Exports ------------------------------------------------------------
  global.TeleDriveS3Credentials = {
    GROUPS: GROUPS,
    ALL: ALL,
    DANGEROUS: DANGEROUS,
    PRESETS: PRESETS,
    riskFor: riskFor,
    selectedCount: selectedCount,
    groupSelection: groupSelection,
    presetGroups: presetGroups,
    risksIn: risksIn,
    relative: relative,
    expiryState: expiryState,
    describeCredential: describeCredential,
    groupLabels: groupLabels,
    byId: function (id) { return PRESET_BY_ID[id] || null; }
  };

  // --- Alpine component fragment -----------------------------------------
  // app.js spreads these into its single x-data object. Keeping every
  // credential method here means the secret-handling code and the catalogue
  // it is audited against live in one file.

  global.credentialState = function () {
    return {
      s3Keys: [],
      s3Loading: false,
      s3LoadError: '',
      s3Search: '',
      s3Collapsed: {},
      s3Editor: null,
      s3Preset: null,
      s3PresetTouched: false,
      s3Created: null,
      s3Revealed: null,
      s3RevokeTarget: null,
      s3RotateTarget: null,
      s3RevealTarget: null,
      s3Busy: false
    };
  };

  global.credentialMethods = function () {
    var C = global.TeleDriveS3Credentials;

    function model(self) {
      return self.s3Editor ? self.s3Editor.permissions : [];
    }

    return {
      s3Groups() { return C.GROUPS; },
      s3Presets() { return C.PRESETS; },

      // Live search across group title, group description and scope name.
      s3VisibleGroups() {
        var q = (this.s3Search || '').trim().toLowerCase();
        if (!q) return C.GROUPS;
        var out = [];
        C.GROUPS.forEach(function (g) {
          var groupHit = g.label.toLowerCase().indexOf(q) >= 0 ||
                         g.description.toLowerCase().indexOf(q) >= 0 ||
                         g.id.toLowerCase().indexOf(q) >= 0;
          var perms = groupHit ? g.perms : g.perms.filter(function (p) {
            return p.toLowerCase().indexOf(q) >= 0;
          });
          if (perms.length) out.push({ id: g.id, label: g.label, description: g.description, perms: perms });
        });
        return out;
      },
      s3GroupOpen(id) { return !this.s3Collapsed[id] || !!this.s3Search; },
      s3ToggleCollapse(id) { this.s3Collapsed[id] = !this.s3Collapsed[id]; },
      s3SearchCount() {
        var q = (this.s3Search || '').trim().toLowerCase();
        if (!q) return 0;
        return model(this).filter(function (p) { return p.toLowerCase().indexOf(q) >= 0; }).length;
      },

      s3Model() { return model(this); },
      s3Total() { return C.ALL.length; },
      s3SelectedCount() { return model(this).length; },
      s3GroupSelection(group) { return C.groupSelection(group, model(this)); },

      s3PermSelected(scope) { return model(this).indexOf(scope) >= 0; },
      s3TogglePerm(scope) {
        var m = model(this);
        var i = m.indexOf(scope);
        if (i >= 0) m.splice(i, 1); else m.push(scope);
        this.s3PresetTouched = true;
      },
      s3SelectGroup(group) {
        var m = model(this);
        group.perms.forEach(function (p) { if (m.indexOf(p) < 0) m.push(p); });
        this.s3PresetTouched = true;
      },
      s3ClearGroup(group) {
        var m = model(this);
        group.perms.forEach(function (p) {
          var i = m.indexOf(p);
          if (i >= 0) m.splice(i, 1);
        });
        this.s3PresetTouched = true;
      },
      s3ToggleGroup(group) {
        if (C.groupSelection(group, model(this)).all) this.s3ClearGroup(group);
        else this.s3SelectGroup(group);
      },
      s3SelectAll() {
        var m = model(this);
        m.splice(0, m.length);
        C.ALL.forEach(function (p) { m.push(p); });
        this.s3PresetTouched = true;
      },
      s3ClearAll() {
        var m = model(this);
        m.splice(0, m.length);
        this.s3PresetTouched = true;
      },

      s3RiskFor(scope) { return C.riskFor(scope); },
      s3Risks() { return C.risksIn(model(this)); },
      s3RiskCount() { return C.risksIn(model(this)).length; },
      s3GroupRisks(group) {
        var self = this;
        return C.risksIn(group.perms.filter(function (p) { return model(self).indexOf(p) >= 0; }));
      },
      s3HasRisk(scope) { return !!C.riskFor(scope); },

      s3ApplyPreset(id) {
        var preset = C.byId(id);
        var m = model(this);
        if (!preset || !m) return;
        m.splice(0, m.length);
        preset.perms.forEach(function (p) { m.push(p); });
        this.s3Preset = {
          id: preset.id,
          label: preset.label,
          consequence: preset.consequence,
          groups: C.presetGroups(preset.id, m)
        };
        this.s3PresetTouched = false;
      },
      s3PresetGroups() {
        if (!this.s3Preset) return [];
        return C.presetGroups(this.s3Preset.id, model(this));
      },

      // Editor ------------------------------------------------------------
      s3OpenCreate() {
        this.s3Editor = {
          mode: 'create', id: '', name: '', access_key: '',
          permissions: ['s3:ListAllMyBuckets', 's3:ListBucket',
                        's3:GetBucketLocation', 's3:GetObject',
                        's3:PutObject'],
          expiryPreset: 90, customExpiry: ''
        };
        this.s3Search = '';
        this.s3Preset = null;
        this.s3PresetTouched = false;
      },
      s3OpenEdit(key) {
        this.s3Editor = {
          mode: 'edit', id: key.id, name: key.name, access_key: key.access_key,
          permissions: (key.permissions || []).slice(),
          expiryPreset: 'keep',
          customExpiry: key.expires_at
            ? new Date(key.expires_at * 1000).toISOString().slice(0, 16) : ''
        };
        this.s3Search = '';
        this.s3Preset = null;
        this.s3PresetTouched = false;
      },
      s3CloseEditor() { this.s3Editor = null; this.s3Preset = null; this.s3Search = ''; },
      s3Escape() {
        if (this.s3RevokeTarget) { this.s3RevokeTarget = null; return; }
        if (this.s3RotateTarget) { this.s3RotateTarget = null; return; }
        if (this.s3RevealTarget) { this.s3RevealTarget = null; return; }
        if (this.s3Editor) { this.s3CloseEditor(); return; }
        if (this.s3Revealed) { this.s3Revealed = null; }
      },
      s3ExpirySeconds(preset, custom) {
        if (preset === 'keep' || preset === 'never') return null;
        if (preset === 'custom') {
          if (!custom) return undefined;
          var ms = new Date(custom).getTime();
          if (isNaN(ms)) return undefined;
          return Math.floor(ms / 1000);
        }
        var days = Number(preset);
        if (!days) return null;
        return Math.floor(Date.now() / 1000) + days * 86400;
      },
      s3EditorValid() {
        if (!this.s3Editor) return false;
        if (!this.s3Editor.name.trim()) return false;
        if (!this.s3Editor.permissions.length) return false;
        if (this.s3Editor.expiryPreset === 'custom') {
          var ts = this.s3ExpirySeconds('custom', this.s3Editor.customExpiry);
          if (ts == null || ts <= Math.floor(Date.now() / 1000)) return false;
        }
        return true;
      },
      async s3SaveEditor() {
        if (!this.s3EditorValid() || this.s3Busy) return;
        var ed = this.s3Editor;
        var expires = this.s3ExpirySeconds(ed.expiryPreset, ed.customExpiry);
        var body = { name: ed.name.trim(), permissions: ed.permissions.slice() };
        if (expires) body.expires_at = expires;
        if (ed.mode === 'edit') {
          if (ed.expiryPreset === 'never') body.clear_expiry = true;
        }
        this.s3Busy = true;
        try {
          if (ed.mode === 'create') {
            var r = await this.api('/api/v1/admin/s3/credentials',
              { method: 'POST', body: JSON.stringify(body) });
            // The secret exists only in this component until the operator
            // dismisses the panel. It is never stored or put in the URL.
            this.s3Created = { name: body.name, access: r.access_key, secret: r.secret_key };
            this.toast('S3 credentials created — copy the secret now');
          } else {
            await this.api('/api/v1/admin/s3/credentials/' + ed.id,
              { method: 'PUT', body: JSON.stringify(body) });
            this.toast('Credential updated');
          }
          this.s3CloseEditor();
          await this.s3Load();
        } catch (e) {
          this.toast(e.message, true);
        } finally {
          this.s3Busy = false;
        }
      },

      // List --------------------------------------------------------------
      async s3Load() {
        this.s3Loading = true;
        this.s3LoadError = '';
        try {
          var r = await this.api('/api/v1/admin/s3/credentials');
          this.s3Keys = r.credentials || [];
        } catch (e) {
          this.s3LoadError = e.message;
        } finally {
          this.s3Loading = false;
        }
      },
      s3Describe(key) { return C.describeCredential(key); },
      s3ExpiryRelative(ts) { return ts ? C.relative(ts) : 'never'; },
      s3LastUsed(key) {
        // last_used_at is tracked for REST API keys, not for S3
        // credentials: the API does not return the field yet.
        return key.last_used_at ? C.relative(key.last_used_at) : null;
      },
      s3GroupLabels(key) { return C.groupLabels(key.permissions); },
      s3KeyRiskCount(key) { return C.risksIn(key.permissions).length; },

      // Rotate / revoke / reveal -----------------------------------------
      s3AskRevoke(key) { this.s3RevokeTarget = key; },
      s3AskRotate(key) { this.s3RotateTarget = key; },
      s3AskReveal(key) { this.s3RevealTarget = key; },

      async s3ConfirmRevoke() {
        var key = this.s3RevokeTarget;
        if (!key || this.s3Busy) return;
        this.s3Busy = true;
        try {
          await this.api('/api/v1/admin/s3/credentials/' + key.id, { method: 'DELETE' });
          this.s3RevokeTarget = null;
          this.toast('Credential revoked — clients using it are rejected now');
          await this.s3Load();
        } catch (e) {
          this.toast(e.message, true);
        } finally {
          this.s3Busy = false;
        }
      },

      // There is no rotate endpoint: the access key and secret are
      // immutable by design. Rotation is issue-new-then-revoke-old, done
      // here in one confirmed step so the old key cannot be left alive.
      async s3ConfirmRotate() {
        var key = this.s3RotateTarget;
        if (!key || this.s3Busy) return;
        this.s3Busy = true;
        var body = {
          name: (key.name + ' (rotated)').slice(0, 120),
          permissions: (key.permissions || []).slice()
        };
        if (key.expires_at) {
          body.expires_at = Math.max(key.expires_at, Math.floor(Date.now() / 1000) + 3600);
        }
        try {
          var r = await this.api('/api/v1/admin/s3/credentials',
            { method: 'POST', body: JSON.stringify(body) });
          this.s3Created = { name: body.name, access: r.access_key, secret: r.secret_key };
          try {
            await this.api('/api/v1/admin/s3/credentials/' + key.id, { method: 'DELETE' });
            this.toast('Rotated — old key revoked, copy the new secret now');
          } catch (e) {
            this.toast('New key created, but revoking the old one failed: ' + e.message, true);
          }
          this.s3RotateTarget = null;
          await this.s3Load();
        } catch (e) {
          this.toast(e.message, true);
        } finally {
          this.s3Busy = false;
        }
      },

      async s3ConfirmReveal() {
        var key = this.s3RevealTarget;
        if (!key || this.s3Busy) return;
        this.s3Busy = true;
        try {
          var r = await this.api('/api/v1/admin/s3/credentials/' + key.id + '/secret');
          this.s3Revealed = { name: key.name, access: r.access_key, secret: r.secret_key };
          this.s3RevealTarget = null;
        } catch (e) {
          this.toast(e.message, true);
        } finally {
          this.s3Busy = false;
        }
      },
      s3DismissSecret(which) {
        if (which === 'created') this.s3Created = null;
        else this.s3Revealed = null;
      }
    };
  };
})(window);
