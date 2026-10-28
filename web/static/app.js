// UI-side noise filter: the logs page's own polling and status requests
// would otherwise flood its live view. Everything stays in the log
// file/buffer; these entries are only hidden from the table.
const LOG_NOISE_RE = /^GET \/api\/v1\/logs( |$)|^GET \/api\/v1\/admin\/storage\/telegram-session\/floodwait( |$)/;

function app(){
  return {
    // State
    toastMsg: '',
    toastBad: false,
    currentUser: '',
    currentRole: '',
    loginUsername: '',
    loginPassword: '',
    loginError: '',

    // Dashboard / queue / history
    dashboard: {pending:0,failed:0,uploaded:0,alerts:0,strategy:'-'},
    dashAccounts: [],
    usageSeries: [],
    gc: {},
    gcScope: 'revoked',
    gcPreview: [],
    async refreshGC(){
      try {
        const r = await this.api('/api/v1/admin/storage/gc');
        this.gc = r;
      } catch(e){ this.toast(e.message,true); }
    },
    async toggleGC(){
      const enabling = !this.gc.state?.enabled;
      const confirmWord = enabling ? prompt('Type PHYSICAL-GC to enable physical deletion of retained Telegram media:') : null;
      if(enabling && confirmWord !== 'PHYSICAL-GC'){ this.toast('Confirmation did not match', true); return; }
      try {
        const r = await this.api('/api/v1/admin/storage/gc',{method:'PUT',body:JSON.stringify({enabled:enabling, confirm:confirmWord})});
        this.gc.state = r.state;
        this.toast(enabling ? 'Physical GC ENABLED — collect now to reclaim' : 'Physical GC disabled');
        await this.refreshGC();
      } catch(e){ this.toast(e.message,true); }
    },
    async collectGC(dryRun){
      const body = {scope:this.gcScope, dry_run:dryRun, limit:50};
      if(!dryRun){
        if(!this.gc.state?.enabled){ this.toast('Enable GC first', true); return; }
        const word = prompt('Type DELETE-RETAINED to physically delete the previewed Telegram media:');
        if(word !== 'DELETE-RETAINED'){ this.toast('Confirmation did not match', true); return; }
        body.confirm = word;
      }
      try {
        const r = await this.api('/api/v1/admin/storage/gc/collect',{method:'POST',body:JSON.stringify(body)});
        if(dryRun){
          this.gcPreview = r.candidates||[];
          this.toast('Preview: ' + r.count + ' candidate(s) [' + this.gcScope + ']');
          await this.refreshGC();
        } else {
          this.toast('Collected ' + (r.collected?.length||0) + ', skipped ' + (r.skipped?.length||0) + ', failed ' + (r.failed?.length||0));
          this.gcPreview = [];
          await this.refreshGC();
          await this.refreshDashboard();
        }
      } catch(e){ this.toast(e.message,true); }
    },
    queueRows: [],
    historyRows: [],
    bucketUsage: [],
    mustChangePassword: false,
    searchQuery: '',
    searchResults: null,
    dropHover: false,
    uploading: false,
    uploadName: '',
    uploadPct: 0,
    selectedKeyList: [],
    selectedKeys: new Set(),
    previewOpen: false,
    previewBucket: '',
    previewKey: '',
    previewKind: 'binary',
    previewSize: 0,
    previewText: '',

    // Settings
    config: null,
    activeChannelId: '',
    activeChannelLabel: 'Loading...',
    channels: [],
    showAddChannel: false,
    newChannelName: '',
    newChannelId: '',
    newChannelStrategy: 'round_robin',
    newChannelScratch: '/data/tmp',
    tgApiId: '',
    tgApiHash: '',
    tgPhone: '',
    tgSessionStatus: 'Not checked',
    tgSessions: [],
    tgChecking: '',
    strategySel: 'round_robin',
    replicaSel: '',
    replication: null,
    tgSessionError: '',
    floodActive: false,
    floodLast: null,
    floodScope: '',
    floodExpiresAt: 0,
    floodNow: Math.floor(Date.now()/1000),
    tgCodeVisible: false,
    tgCode: '',
    tgPassword: '',
    tgSessionToken: null,
    extensionsStr: '',

    // API keys
    apiKeys: [],
    newKeyName: '',
    newKeyExpiry: '',
    newKeyExpiryPreset: 30,
    createOpen: false,
    permSearch: '',
    catOpen: {},
    keyScopesList: ['objects:read','objects:write','objects:delete','buckets:read','buckets:manage','jobs:read','jobs:manage','accounts:read','accounts:manage','settings:read','settings:manage','keys:manage','admin:*'],
    endpointPermissions: [],
    endpointGroups: [],
    groupDescriptions: {},
    legacyScopes: [],
    endpointCategories: {},
    async loadPermissionCatalog(){
      try {
        const r = await this.api('/api/v1/admin/keys/permissions');
        this.legacyScopes = r.legacy_scopes||[];
        const routes = r.routes||[];
        this.endpointPermissions = routes;
        this.endpointGroups = r.groups||[];
        // Group routes by path with {params} as '*' (trailing /* dropped).
        const cats = {};
        const groupDesc = {};
        for(const g of this.endpointGroups){
          groupDesc[g.name] = g.description;
        }
        for(const p of routes){
          let cat = p.path.replace(/\{[^}]+\}/g, '*');
          if(cat.endsWith('/*')) cat = cat.slice(0, -2);
          (cats[cat] = cats[cat]||[]).push(p.name);
        }
        this.endpointCategories = cats;
        this.groupDescriptions = groupDesc;
      } catch(e){ /* catalog is best-effort; manual scope entry still works */ }
    },
    toggleAllEndpoints(on){
      const names = this.endpointPermissions.map(p => p.name);
      if(on){ this.selectedScopes = [...new Set([...this.selectedScopes, ...names])]; }
      else { this.selectedScopes = this.selectedScopes.filter(s => !names.includes(s) && s !== 'admin:*'); }
    },
    toggleEndpointCategory(cat){
      const names = this.endpointCategories[cat]||[];
      if(this.categoryFullySelected(cat)){
        this.selectedScopes = this.selectedScopes.filter(s => !names.includes(s));
      } else {
        this.selectedScopes = [...new Set([...this.selectedScopes, ...names])];
      }
    },
    categoryFullySelected(cat){
      return (this.endpointCategories[cat]||[]).every(n => this.selectedScopes.includes(n));
    },
    endpointsIn(cat){
      const names = new Set(this.endpointCategories[cat]||[]);
      return this.endpointPermissions.filter(p => names.has(p.name));
    },
    countSelected(names){ return names.filter(n => this.selectedScopes.includes(n)).length; },
    toggleCatOpen(cat){ this.catOpen[cat] = !this.catOpen[cat]; },
    categoryMatches(cat){
      if(!this.permSearch) return true;
      const q = this.permSearch.toLowerCase();
      return cat.toLowerCase().includes(q) ||
        this.endpointsIn(cat).some(p => this.permMatches(p));
    },
    permMatches(p){
      if(!this.permSearch) return true;
      const q = this.permSearch.toLowerCase();
      return p.name.toLowerCase().includes(q) ||
        p.method.toLowerCase().includes(q) ||
        p.path.toLowerCase().includes(q) ||
        (p.description||'').toLowerCase().includes(q);
    },
    fmtRel(v){
      if(!v) return '-';
      const s = Math.floor(Date.now()/1000) - v;
      if (s < 60) return 'just now';
      if (s < 3600) return Math.floor(s/60) + ' min ago';
      if (s < 86400) return Math.floor(s/3600) + 'h ago';
      if (s < 30*86400) return Math.floor(s/86400) + 'd ago';
      if (s < 365*86400) return Math.floor(s/(30*86400)) + 'mo ago';
      const future = s < 0;
      const y = Math.floor(Math.abs(s)/(365*86400));
      return future ? ('in ' + (y?y+'y':Math.floor(Math.abs(s)/(30*86400))+'mo')) : y + 'y ago';
    },
    keyExpired(k){
      return !!(k.expires_at && k.expires_at <= Math.floor(Date.now()/1000));
    },
    selectedScopes: ['objects:read','objects:write','objects:delete','buckets:read','buckets:manage'],
    createdKey: null,

    // S3
    s3KeyName: '',
    s3CreateOpen: false,
    s3ExpiryPreset: 90,
    s3KeyExpiry: '',
    s3Perms: ['s3:ListAllMyBuckets','s3:ListBucket','s3:GetBucketLocation','s3:GetObject','s3:GetObjectAttributes','s3:GetObjectTagging','s3:PutObjectTagging','s3:DeleteObjectTagging','s3:GetBucketTagging','s3:GetBucketCORS','s3:PutBucketCORS','s3:PutBucketTagging','s3:DeleteBucketTagging','s3:PutObject','s3:DeleteObject','s3:CreateBucket','s3:DeleteBucket'],
    selectedS3Perms: ['s3:ListAllMyBuckets','s3:ListBucket','s3:GetBucketLocation','s3:GetObject','s3:PutObject','s3:DeleteObject'],
    s3Keys: [],
    s3Edit: null,
    revealedS3: null,
    // Permission groups for the S3 credential grids (create + edit).
    s3PermGroups: [
      {label: 'Read', hint: 'List buckets/objects and download content', perms: [
        's3:ListAllMyBuckets', 's3:ListBucket', 's3:ListBucketVersions',
        's3:GetBucketLocation', 's3:GetObject', 's3:GetObjectAttributes']},
      {label: 'Write objects', hint: 'Upload, overwrite and delete objects', perms: [
        's3:PutObject', 's3:DeleteObject']},
      {label: 'Object tagging', hint: 'Read and manage object tags', perms: [
        's3:GetObjectTagging', 's3:PutObjectTagging', 's3:DeleteObjectTagging']},
      {label: 'Bucket administration', hint: 'Create/delete buckets and manage settings', perms: [
        's3:CreateBucket', 's3:DeleteBucket', 's3:GetBucketTagging',
        's3:PutBucketTagging', 's3:DeleteBucketTagging', 's3:GetBucketCORS',
        's3:PutBucketCORS', 's3:GetBucketVersioning', 's3:PutBucketVersioning',
        's3:GetLifecycleConfiguration', 's3:PutLifecycleConfiguration']},
      {label: 'Compatibility probes (read-only)', hint: 'AWS-shaped read responses for client compatibility', perms: [
        's3:GetBucketAcl', 's3:GetObjectAcl', 's3:GetOwnershipControls',
        's3:GetBucketPolicy', 's3:GetBucketPolicyStatus',
        's3:GetBucketPublicAccessBlock', 's3:PutBucketPublicAccessBlock',
        's3:GetAccelerateConfiguration', 's3:GetBucketLogging',
        's3:GetBucketNotification', 's3:GetBucketObjectLockConfiguration',
        's3:GetBucketReplication', 's3:GetBucketRequestPayment',
        's3:GetBucketWebsite', 's3:GetEncryptionConfiguration',
        's3:GetObjectLegalHold', 's3:GetObjectRetention']},
    ],
    createdS3: null,

    // Logs
    logEntries: [],
    logLive: false,
    _logTimer: null,
    logFilter: '',
    logLimit: 1000,
    logHideNoise: true,
    logHiddenCount: 0,

    // Buckets
    buckets: [],
    currentBucket: null,
    bucketObjects: [],
    showNewBucket: false,
    newBucketName: '',
    quotaEditBucket: null,
    quotaMaxSize: '',
    quotaMaxObjects: '',

    // Users
    users: [],
    showNewUser: false,
    newUser: {username:'', password:'', role:'viewer'},

    // Role helpers
    get isAdmin(){ return this.currentRole === 'admin'; },
    get canWrite(){ return this.currentRole === 'admin' || this.currentRole === 'operator'; },

    async init(){
      const path = window.location.pathname.replace(/\/+$/, '') || '/';
      if(path === '/login') return;
      try {
        const me = await this.api('/api/v1/auth/me');
        this.currentUser = me.user.username;
        this.currentRole = me.user.role;
        this.mustChangePassword = !!me.must_change_password;
      } catch(e){
        window.location.href = '/login';
        return;
      }
      // While the default admin/admin credential is still in use, every
      // page forces the change-password screen.
      if(this.mustChangePassword && path !== '/users'){
        window.location.replace('/users');
        return;
      }
      if(path === '/' || path === '/dashboard' || path === '/queue'){
        await this.refreshDashboard();
        await this.refreshGC();
        setInterval(()=>this.refreshDashboard(), 30000);
      } else if(path === '/settings/general'){
        await this.loadSettings();
      } else if(path === '/settings/telegram'){
        await this.loadSettings();
        await this.refreshFlood();
        setInterval(()=>this.refreshFlood(), 30000);
        setInterval(()=>{ this.floodNow = Math.floor(Date.now()/1000); }, 1000);
      } else if(path === '/s3/buckets'){
        await this.refreshBuckets();
        await this.refreshShares();
      } else if(path === '/s3/credentials'){
        await this.refreshS3Keys();
      } else if(path === '/s3/governance'){
        await this.govInit();
      } else if(path === '/users'){
        await this.loadUsers();
      } else if(path === '/logs'){
        await this.loadLogs();
      } else if(path === '/api-management'){
        await this.refreshKeys();
        await this.loadPermissionCatalog();
      } else if(path === '/history'){
        await this.refreshHistory();
      }
    },

    navActive(p){ return window.location.pathname === p; },

    usagePct(bytes){
      const max = Math.max(...this.usageSeries.map(d => d.bytes), 1);
      return Math.max(3, Math.round(bytes / max * 100));
    },

    // One consistent confirmation helper for every destructive action:
    // same phrasing, same "consequence" hint, same audit note when the
    // action is logged.
    confirmDelete(what, hint){
      return confirm('Delete ' + what + '?' + (hint ? '\n\n' + hint : ''));
    },
    toast(msg, bad=false){
      this.toastMsg = msg;
      this.toastBad = bad;
      setTimeout(()=>{ this.toastMsg = ''; }, 4000);
    },

    async api(url, opt={}){
      // Session auth flows through the httpOnly teledrive_session cookie
      // (credentials:'include'); no token is kept in localStorage.
      const headers = {'Content-Type':'application/json','X-TeleDrive-CSRF':'1',...(opt.headers||{})};
      const r = await fetch(url, {credentials:'include', headers, ...opt});
      if(!r.ok){
        let msg = r.statusText;
        try {
          const b = JSON.parse(await r.text());
          if(typeof b.detail === 'string') msg = b.detail;
          else if(b.detail && typeof b.detail === 'object' && b.detail.message) msg = b.detail.message;
        } catch(e){}
        throw new Error(msg);
      }
      return r.json();
    },

    fmtTs(v){ if(!v) return '-'; return new Date(v*1000).toLocaleString(); },

    async refreshDashboard(){
      try {
        const r = await this.api('/api/v1/admin/storage/health');
        const s = r.job_states||{};
        this.dashboard = {
          pending: (s.queued||0)+(s.running||0)+(s.staged||0)+(s.publishing||0),
          failed: s.failed||0,
          uploaded: s.done||s.completed||0,
          alerts: r.unresolved_alert_count||0,
          strategy: this.dashboard.strategy
        };
      } catch(e){}
      try {
        const a = await this.api('/api/v1/admin/storage/active-channel');
        this.dashboard.strategy = (a.active && a.active.strategy) || '-';
      } catch(e){}
      try {
        const r = await this.api('/api/v1/admin/storage/telegram-sessions');
        this.dashAccounts = r.sessions||[];
        if(r.strategy) this.dashboard.strategy = r.strategy;
      } catch(e){}
      try {
        const r = await this.api('/api/v1/admin/storage/usage?days=30');
        this.usageSeries = r.series||[];
      } catch(e){}
      try {
        const r = await this.api('/api/v1/admin/storage/jobs?limit=100');
        this.queueRows = (r.jobs||[]).map(j => ({...j, path: j.source_path, status: j.state}));
      } catch(e){}
      try {
        const r = await this.api('/api/v1/admin/storage/buckets');
        this.bucketUsage = r.buckets||[];
      } catch(e){}
    },

    async refreshHistory(){
      try {
        const r = await this.api('/api/v1/admin/storage/jobs?limit=100');
        const terminal = ['done','completed','failed','cancelled'];
        this.historyRows = (r.jobs||[])
          .filter(j => terminal.includes(j.state))
          .map(j => ({
            path: j.source_path,
            tg_account: j.account||'-',
            tg_message_id: j.object_id||'-',
            uploaded_ts: j.updated_at
          }));
      } catch(e){ this.toast(e.message,true); }
      await this.refreshBuckets();
      await this.refreshVersions();
    },
    versionRows: [],
    versionBucket: '',
    async refreshVersions(){
      try {
        const q = this.versionBucket ? ('?bucket=' + encodeURIComponent(this.versionBucket)) : '';
        const r = await this.api('/api/v1/admin/storage/version-history'+q);
        this.versionRows = r.versions||[];
      } catch(e){ this.toast(e.message,true); }
    },

    async login(){
      try {
        await this.api('/api/v1/auth/login',{method:'POST',body:JSON.stringify({username:this.loginUsername,password:this.loginPassword})});
        window.location.replace('/');
      } catch(e){ this.loginError = e.message; }
    },
    async logout(){
      try { await this.api('/api/v1/auth/logout',{method:'POST'}); } catch(e){}
      window.location.replace('/login');
    },
    async loadSettings(){
      try {
        const config = await this.api('/api/v1/config');
        const tg = config.telegram||{}, up = config.upload||{}, st = config.state||{}, app = config.app||{};
        const storage = config.storage||{}, jobs = config.jobs||{};
        this.config = config;
        if(!this.config.storage) this.config.storage = {};
        if(!this.config.upload) this.config.upload = {};
        if(!this.config.state) this.config.state = {};
        if(!this.config.app) this.config.app = {};
        if(!this.config.telegram) this.config.telegram = {};
        this.config.storage.channel = storage.channel||'';
        this.config.storage.strategy = storage.strategy||'round_robin';
        this.config.storage.scratch_dir = storage.scratch_dir||'/data/tmp';
        this.config.upload.source_dir = up.source_dir||'/uploads';
        this.config.upload.send_mode = up.send_mode||'document';
        this.config.upload.max_files_per_run = up.max_files_per_run??12;
        this.config.upload.max_files_per_day = up.max_files_per_day??100;
        this.config.upload.sleep_min_seconds = up.sleep_min_seconds??60;
        this.config.upload.sleep_max_seconds = up.sleep_max_seconds??90;
        this.config.upload.retry_attempts = up.retry_attempts??5;
        this.config.upload.backoff_base_seconds = up.backoff_base_seconds??10;
        this.config.upload.floodwait_buffer_seconds = up.floodwait_buffer_seconds??5;
        this.config.upload.max_file_size_mb = up.max_file_size_mb??0;
        this.config.upload.caption_template = up.caption_template||'{name}';
        this.config.upload.allowed_extensions = up.allowed_extensions||[];
        this.extensionsStr = (up.allowed_extensions||[]).join(',');
        this.config.state.database_url = st.database_url||st.db_path||'sqlite:////data/state.db';
        this.config.app.auto_run = !!app.auto_run;
        this.config.app.run_interval_minutes = app.run_interval_minutes??60;
        this.activeChannelId = storage.channel||'';
        await this.refreshChannels();
        await this.refreshTgSessionStatus();
        await this.loadReplication();
      } catch(e){ this.toast(e.message,true); }
    },

    async saveSettings(){
      try {
        if(!this.config) await this.loadSettings();
        const c = this.config;
        c.storage.channel = this.activeChannelId || (this.channels[0]?.channel_id||'');
        c.storage.strategy = c.storage.strategy||'round_robin';
        c.storage.scratch_dir = c.storage.scratch_dir||'/data/tmp';
        c.upload.allowed_extensions = this.extensionsStr.split(',').map(x=>x.trim()).filter(Boolean);
        delete c.state.db_path;
        await this.api('/api/v1/config',{method:'PUT',body:JSON.stringify(c)});
        this.toast('Settings saved');
      } catch(e){ this.toast(e.message,true); }
    },

    async refreshChannels(){
      try {
        const r = await this.api('/api/v1/admin/storage/channels');
        this.channels = r.channels||[];
        const a = await this.api('/api/v1/admin/storage/active-channel');
        if(a.active){ this.activeChannelId = a.active.id; this.activeChannelLabel = 'Active: '+a.active.name+' ('+a.active.channel_id+')'; }
        else { this.activeChannelLabel = 'No active channel.'; }
      } catch(e){ this.toast(e.message,true); }
    },

    async addChannel(){
      try {
        await this.api('/api/v1/admin/storage/channels',{method:'POST',body:JSON.stringify({name:this.newChannelName.trim(),channel_id:this.newChannelId.trim(),strategy:this.newChannelStrategy,scratch_dir:this.newChannelScratch.trim()||'/data/tmp'})});
        this.toast('Channel added');
        this.showAddChannel = false;
        this.newChannelName = '';
        this.newChannelId = '';
        await this.refreshChannels();
      } catch(e){ this.toast(e.message,true); }
    },

    async activateChannel(id){
      try { await this.api('/api/v1/admin/storage/channels/'+id+'/activate',{method:'POST'}); this.toast('Activated'); await this.refreshChannels(); }
      catch(e){ this.toast(e.message,true); }
    },

    async deleteChannel(id){
      if(!this.confirmDelete('this channel', 'Uploads targeting it must be re-assigned.')) return;
      try { await this.api('/api/v1/admin/storage/channels/'+id,{method:'DELETE'}); this.toast('Removed'); await this.refreshChannels(); }
      catch(e){ this.toast(e.message,true); }
    },

    async refreshTgSessionStatus(){
      try {
        const r = await this.api('/api/v1/admin/storage/telegram-sessions');
        this.tgSessions = r.sessions||[];
        if(r.strategy) this.strategySel = r.strategy;
        this.tgSessionStatus = this.tgSessions.length
          ? this.tgSessions.length+' account(s) authorized'
          : 'No session configured.';
      } catch(e){ this.tgSessionStatus = 'Error: '+e.message; }
    },
    async saveStrategy(){
      try {
        await this.api('/api/v1/admin/storage/strategy',{method:'PUT',body:JSON.stringify({strategy:this.strategySel})});
        this.toast('Strategy saved: '+this.strategySel);
      } catch(e){
        this.toast(e.message,true);
        await this.refreshTgSessionStatus();
      }
    },
    async loadReplication(){
      try {
        this.replication = await this.api('/api/v1/admin/storage/replication');
        this.replicaSel = this.replication.account || '';
      } catch(e){ /* status card is best-effort */ }
    },
    async saveReplication(){
      try {
        await this.api('/api/v1/admin/storage/replication',{method:'PUT',body:JSON.stringify({account:this.replicaSel})});
        this.toast(this.replicaSel ? 'Replication target: '+this.replicaSel : 'Replication disabled');
        await this.loadReplication();
      } catch(e){
        this.toast(e.message,true);
        await this.loadReplication();
      }
    },
    async repairReplication(){
      try {
        const r = await this.api('/api/v1/admin/storage/replication/repair',{method:'POST',body:JSON.stringify({limit:10})});
        this.toast(r.repaired_objects
          ? 'Repaired '+r.repaired_objects+' object(s), '+r.chunks+' chunk(s)'
          : 'Nothing to repair');
        await this.loadReplication();
      } catch(e){ this.toast(e.message,true); }
    },
    quotaEditAccount: null,
    quotaEditBytes: '',
    async editAccountQuota(s){
      this.quotaEditAccount = s.account;
      this.quotaEditBytes = s.soft_quota_bytes || '';
    },
    async saveAccountQuota(){
      const raw = String(this.quotaEditBytes).trim();
      const value = raw === '' ? null : Number(raw);
      try {
        await this.api('/api/v1/admin/storage/telegram-sessions/'+encodeURIComponent(this.quotaEditAccount)+'/quota',
          {method:'PUT', body: JSON.stringify({soft_quota_bytes: value})});
        this.toast('Soft quota saved');
        this.quotaEditAccount = null;
        await this.refreshTgSessionStatus();
      } catch(e){ this.toast(e.message,true); }
    },
    async checkTgSession(account){
      this.tgChecking = account;
      try {
        const r = await this.api('/api/v1/admin/storage/telegram-sessions/'+encodeURIComponent(account)+'/health-check',{method:'POST'});
        this.toast(r.authorized ? 'Account OK: '+account : 'UNAUTHORIZED: '+account+' — re-login needed', !r.authorized);
        await this.refreshTgSessionStatus();
      } catch(e){ this.toast(e.message,true); }
      finally { this.tgChecking = ''; }
    },
    async deleteTgSession(account, force){
      const hasData = this.tgSessions.find(s=>s.account===account)?.objects > 0;
      const msg = hasData && !force
        ? 'The account '+account+' still stores objects. Delete its session anyway? (Reads of those objects will need the account re-authorized.)'
        : 'Delete the Telegram session for '+account+'?';
      if(!confirm(msg)) return;
      try {
        await this.api('/api/v1/admin/storage/telegram-sessions/'+encodeURIComponent(account)
          +(force?'?force=true':''), {method:'DELETE'});
        this.toast('Session deleted: '+account);
        await this.refreshTgSessionStatus();
      } catch(e){
        // 409 soft-guard: confirm once more with the data warning shown
        if(e.message && e.message.includes('still stores objects')){
          if(confirm(e.message+'\n\nDelete anyway?')) return this.deleteTgSession(account, true);
        } else this.toast(e.message,true);
      }
    },
    async refreshFlood(){
      try {
        const r = await this.api('/api/v1/admin/storage/telegram-session/floodwait');
        this.floodLast = r.last||null;
        this.floodActive = !!r.active;
        if(r.last){
          this.floodScope = r.last.scope;
          this.floodExpiresAt = r.last.expires_at;
        }
      } catch(e){}
    },
    get floodCountdown(){
      const rem = Math.max(0, this.floodExpiresAt - this.floodNow);
      const h = Math.floor(rem/3600), m = Math.floor((rem%3600)/60), sec = rem%60;
      return h ? (h+'h '+String(m).padStart(2,'0')+'m') : (m ? (m+'m '+String(sec).padStart(2,'0')+'s') : (sec+'s'));
    },
    get floodExpiresLocal(){
      if(!this.floodExpiresAt) return '-';
      return new Date(this.floodExpiresAt*1000).toLocaleTimeString();
    },
    get floodLastText(){
      if(!this.floodLast) return '';
      const d = new Date(this.floodLast.started_at*1000).toLocaleString();
      return this.floodLast.scope+' ('+Math.round(this.floodLast.wait_seconds/60)+' min, '+d+')';
    },

    async sendTgCode(){
      this.tgSessionError = '';
      try {
        const body = {
          api_id: Number(this.tgApiId||0),
          api_hash: this.tgApiHash.trim(),
          phone: this.tgPhone.trim(),
          channel: this.activeChannelId ? (this.channels.find(c=>c.id==this.activeChannelId)?.channel_id||null) : null,
          strategy: this.config?.storage?.strategy||'round_robin'
        };
        const r = await this.api('/api/v1/admin/storage/telegram-session/request-code',{method:'POST',body:JSON.stringify(body)});
        this.tgSessionToken = r.token;
        this.tgCodeVisible = true;
        this.toast('Code sent to Telegram app');
      } catch(e){
        this.tgSessionError = e.message;
        this.toast(e.message,true);
        await this.refreshFlood();
      }
    },

    async verifyTgCode(){
      this.tgSessionError = '';
      try {
        const body = { token: this.tgSessionToken, code: this.tgCode.trim(), password: this.tgPassword||null };
        const r = await this.api('/api/v1/admin/storage/telegram-session/verify-code',{method:'POST',body:JSON.stringify(body)});
        this.toast('Session saved: '+r.account);
        this.tgSessionToken = null;
        this.tgCodeVisible = false;
        this.tgCode = '';
        this.tgPassword = '';
        await this.refreshTgSessionStatus();
        await this.loadSettings();
      } catch(e){
        this.tgSessionError = e.message;
        this.toast(e.message,true);
      }
    },

    async runJob(){
      try { await this.api('/api/v1/admin/storage/jobs/run-next',{method:'POST'}); this.toast('Job triggered'); await this.refreshDashboard(); }
      catch(e){ this.toast(e.message,true); }
    },

    async refreshKeys(){
      try { const r = await this.api('/api/v1/admin/keys'); this.apiKeys = r.keys||[]; }
      catch(e){ this.toast(e.message,true); }
    },

    async createKey(){
      try {
        const scopes = this.selectedScopes.slice();
        const body = {name:this.newKeyName.trim()||'key', scopes:scopes};
        if(this.newKeyExpiryPreset === 'custom'){
          if(this.newKeyExpiry) body.expires_at = Math.floor(new Date(this.newKeyExpiry).getTime()/1000);
        } else if(Number(this.newKeyExpiryPreset) > 0){
          body.expires_at = Math.floor(Date.now()/1000) + Number(this.newKeyExpiryPreset)*86400;
        }
        const r = await this.api('/api/v1/admin/keys',{method:'POST',body:JSON.stringify(body)});
        this.createdKey = {prefix:r.prefix, token:r.token};
        this.toast('Key created');
        this.createOpen = false;
        await this.refreshKeys();
      } catch(e){ this.toast(e.message,true); }
    },

    async rotateKey(id){
      if(!this.confirmDelete('rotate this API key', 'The current secret stops working immediately; the replacement is shown once.')) return;
      try {
        const r = await this.api('/api/v1/admin/keys/'+id+'/rotate',{method:'POST'});
        this.createdKey = {prefix:r.prefix, token:r.token};
        this.toast('Key rotated — copy the new secret');
        await this.refreshKeys();
      } catch(e){ this.toast(e.message,true); }
    },

    async revokeKey(id){
      if(!this.confirmDelete('this API key', 'Clients using it stop working immediately.')) return;
      try { await this.api('/api/v1/admin/keys/'+id,{method:'DELETE'}); this.toast('Revoked'); await this.refreshKeys(); }
      catch(e){ this.toast(e.message,true); }
    },

    async copyText(t){
      try{ await navigator.clipboard.writeText(t); this.toast('Copied'); }catch(e){ this.toast('Clipboard unavailable',true); }
    },

    async revokeS3Key(id){
      if(!this.confirmDelete('this S3 credential', 'S3 clients signed with it stop working immediately.')) return;
      try { await this.api('/api/v1/admin/s3/credentials/'+id,{method:'DELETE'}); this.toast('Revoked'); await this.refreshS3Keys(); }
      catch(e){ this.toast(e.message,true); }
    },

    async revealS3Secret(k){
      if(!confirm('Reveal the secret for '+k.name+'? This action is audit-logged.')) return;
      try {
        this.revealedS3 = await this.api('/api/v1/admin/s3/credentials/'+k.id+'/secret');
      } catch(e){ this.toast(e.message,true); }
    },
    togglePermGroup(perms, editTarget){
      const model = editTarget ? editTarget.permissions : this.selectedS3Perms;
      const allOn = perms.every(p => model.includes(p));
      for(const p of perms){
        const i = model.indexOf(p);
        if(allOn && i >= 0) model.splice(i, 1);
        else if(!allOn && i < 0) model.push(p);
      }
    },
    startS3Edit(k){
      this.s3Edit = {id: k.id, access_key: k.access_key, name: k.name,
                     permissions: [...(k.permissions||[])]};
    },
    async saveS3Edit(){
      try {
        await this.api('/api/v1/admin/s3/credentials/'+this.s3Edit.id,
          {method:'PUT', body: JSON.stringify({name: this.s3Edit.name.trim(),
            permissions: this.s3Edit.permissions})});
        this.toast('Credential updated');
        this.s3Edit = null;
        await this.refreshS3Keys();
      } catch(e){ this.toast(e.message,true); }
    },
    async refreshS3Keys(){
      try { const r = await this.api('/api/v1/admin/s3/credentials'); this.s3Keys = r.credentials||[]; }
      catch(e){ this.toast(e.message,true); }
    },

    async createS3Key(){
      try {
        const body = {name:this.s3KeyName.trim()||'s3-key', permissions:this.selectedS3Perms.slice()};
        if(this.s3ExpiryPreset === 'custom'){
          if(this.s3KeyExpiry) body.expires_at = Math.floor(new Date(this.s3KeyExpiry).getTime()/1000);
        } else if(Number(this.s3ExpiryPreset) > 0){
          body.expires_at = Math.floor(Date.now()/1000) + Number(this.s3ExpiryPreset)*86400;
        }
        const r = await this.api('/api/v1/admin/s3/credentials',{method:'POST',body:JSON.stringify(body)});
        this.createdS3 = {access:r.access_key, secret:r.secret_key};
        this.toast('S3 credentials created');
        this.s3CreateOpen = false;
        await this.refreshS3Keys();
      } catch(e){ this.toast(e.message,true); }
    },

    async loadLogs(){
      try {
        const limit = this.logLimit || 1000;
        const filter = (this.logFilter||'').trim().toLowerCase();
        const x = await this.api('/api/v1/logs?limit='+limit);
        let entries = x.entries||[];
        this.logHiddenCount = this.logHideNoise
          ? entries.filter(e => e.source==='http' && LOG_NOISE_RE.test(e.message)).length : 0;
        if(this.logHideNoise) entries = entries.filter(e => !(e.source==='http' && LOG_NOISE_RE.test(e.message)));
        if(filter) entries = entries.filter(e => (e.ts+' '+e.user+' '+e.source+' '+e.message).toLowerCase().includes(filter));
        this.logEntries = entries;
      } catch(e){ this.toast(e.message,true); }
    },
    fmtBytes(b){ if(b==null) return '-'; if(b<1024) return b+' B'; if(b<1048576) return (b/1024).toFixed(1)+' KB'; if(b<1073741824) return (b/1048576).toFixed(1)+' MB'; return (b/1073741824).toFixed(2)+' GB'; },
    quotaPct(used, max){ if(!max) return 0; return Math.min(100, Math.round(100*used/max)); },
    presignKey: null,
    presignBucket: '',
    presignExpiry: 3600,
    presignedUrl: '',
    async presignObject(bucket, key){
      this.presignBucket = bucket;
      this.presignKey = key;
      this.presignedUrl = '';
      try {
        const r = await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/presign',
          {method:'POST', body: JSON.stringify({key, expires: Number(this.presignExpiry)||3600})});
        this.presignedUrl = r.url;
        this.toast('Presigned link generated (' + r.expires_in + 's)');
      } catch(e){ this.toast(e.message,true); }
    },
    corsBucket: null,
    pinBucket: null,
    pinAccount: '',
    shareKey: null,
    shareBucket: '',
    shareExpiry: '',
    shareMaxDownloads: '',
    sharePassword: '',
    shareUrl: '',
    shares: [],
    shareOrigin: window.location.origin,
    async shareObject(bucket, key){
      this.shareBucket = bucket;
      this.shareKey = key;
      this.shareUrl = '';
      this.shareExpiry = '86400';
      this.shareMaxDownloads = '';
      this.sharePassword = '';
      await this.refreshShares();
    },
    async createShare(){
      try {
        const body = {key: this.shareKey};
        if(this.shareExpiry) body.expires_in = Number(this.shareExpiry);
        if(this.shareMaxDownloads) body.max_downloads = Number(this.shareMaxDownloads);
        if(this.sharePassword) body.password = this.sharePassword;
        const r = await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(this.shareBucket)+'/shares',
          {method:'POST', body: JSON.stringify(body)});
        this.shareUrl = this.shareOrigin + r.path;
        this.toast('Share link created');
        await this.refreshShares();
      } catch(e){ this.toast(e.message,true); }
    },
    async refreshShares(){
      try {
        const r = await this.api('/api/v1/admin/storage/shares');
        this.shares = r.shares;
      } catch(e){ /* shares list is best-effort */ }
    },
    async revokeShare(token){
      if(!this.confirmDelete('revoke this share link')) return;
      try {
        await this.api('/api/v1/admin/storage/shares/'+encodeURIComponent(token), {method:'DELETE'});
        this.toast('Share link revoked');
        await this.refreshShares();
      } catch(e){ this.toast(e.message,true); }
    },
    async editPin(bucket){
      this.pinBucket = bucket;
      await this.refreshTgSessionStatus();
      try {
        const r = await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/pin');
        this.pinAccount = r.account || '';
      } catch(e){ this.toast(e.message,true); }
    },
    async savePin(){
      try {
        if(this.pinAccount){
          await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(this.pinBucket)+'/pin',
            {method:'PUT', body: JSON.stringify({account: this.pinAccount})});
          this.toast('Pin saved: '+this.pinAccount);
        } else {
          await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(this.pinBucket)+'/pin',
            {method:'DELETE'});
          this.toast('Pin removed');
        }
        this.pinBucket = null;
      } catch(e){ this.toast(e.message,true); }
    },
    corsRules: [],
    async editCors(bucket){
      this.corsBucket = bucket;
      try {
        const r = await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/cors');
        this.corsRules = (r.rules||[]).map(r => ({
          origins: (r.origins||[]).join(','),
          methods: (r.methods||[]).join(','),
          allowed_headers: (r.allowed_headers||[]).join(',') || '*',
          max_age: r.max_age||0,
        }));
        if(!this.corsRules.length) this.corsRules = [{origins:'',methods:'GET',allowed_headers:'*',max_age:0}];
      } catch(e){ this.toast(e.message,true); }
    },
    async saveCors(){
      const rules = this.corsRules.map(r => ({
        origins: r.origins.split(',').map(x=>x.trim()).filter(Boolean),
        methods: r.methods.split(',').map(x=>x.trim()).filter(Boolean),
        allowed_headers: r.allowed_headers.split(',').map(x=>x.trim()).filter(Boolean),
        max_age: Number(r.max_age)||0,
      })).filter(r => r.origins.length && r.methods.length);
      try {
        await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(this.corsBucket)+'/cors',
          {method:'PUT', body: JSON.stringify({rules})});
        this.toast('CORS rules saved');
      } catch(e){ this.toast(e.message,true); }
    },
    downloadObject(bucket, key){
      window.open('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/content?key='+encodeURIComponent(key), '_blank');
    },
    contentUrl(bucket, key){
      return '/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/content?key='+encodeURIComponent(key);
    },
    previewUrl(){ return this.contentUrl(this.previewBucket, this.previewKey); },
    previewKindFor(key){
      const ext = (key.split('.').pop()||'').toLowerCase();
      if(['png','jpg','jpeg','gif','webp','bmp','svg'].includes(ext)) return 'image';
      if(['mp4','webm','mkv','mov'].includes(ext)) return 'video';
      if(['mp3','ogg','wav','flac','m4a'].includes(ext)) return 'audio';
      if(['txt','json','csv','md','log','xml','yaml','yml','ini','conf','py','js','html','css','sh'].includes(ext)) return 'text';
      return 'binary';
    },
    async previewObject(bucket, key){
      if(this.isEncKey(bucket, key)){ this.toast('Client-side encrypted object — download it to decrypt (no inline preview).', true); return; }
      this.previewBucket = bucket; this.previewKey = key;
      this.previewKind = this.previewKindFor(key);
      this.previewText = '';
      this.previewOpen = true;
      if(this.previewKind === 'text'){
        try {
          const r = await fetch(this.contentUrl(bucket,key), {credentials:'include', headers:{'range':'bytes=0-8191'}});
          if(r.ok || r.status===206) this.previewText = await r.text();
          else this.previewKind = 'binary';
        } catch(e){ this.previewKind = 'binary'; }
      }
      if(this.previewKind === 'binary'){
        try { this.previewSize = 0; } catch(e){}
      }
    },
    async searchObjects(){
      const q = (this.searchQuery||'').trim();
      if(!q){ this.searchResults = null; return; }
      try {
        const r = await this.api('/api/v1/admin/storage/search?'+new URLSearchParams({q, mode: this.searchMode||'key'}));
        this.searchResults = r.objects||[];
        if(!this.searchResults.length) this.toast('No objects matched');
      } catch(e){ this.toast(e.message,true); }
    },
    searchMode: 'key',
    async reindexContents(){
      try {
        const r = await this.api('/api/v1/admin/storage/search/reindex',{method:'POST',body:JSON.stringify({limit:50})});
        this.toast(r.indexed ? 'Indexed '+r.indexed+' object(s)' : 'Nothing left to index');
      } catch(e){ this.toast(e.message,true); }
    },
    syncSelectedKeys(){ this.selectedKeys = new Set(this.selectedKeyList); },
    async deleteSelected(){
      if(!this.selectedKeys.size || !this.confirmDelete(this.selectedKeys.size + ' object(s)', 'Telegram media is retained (physical GC is owner-gated).')) return;
      let ok = 0;
      for(const key of this.selectedKeys){
        try {
          await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(this.currentBucket)+'/objects?'+new URLSearchParams({key}), {method:'DELETE'});
          ok++;
        } catch(e){}
      }
      this.selectedKeyList = []; this.syncSelectedKeys();
      this.toast('Deleted ' + ok + ' object(s)');
      await this.browseBucket(this.currentBucket);
      await this.refreshBuckets();
    },
    async renameObject(bucket, key){
      const parts = key.split('/');
      const name = parts.pop();
      const dir = parts.length ? parts.join('/') + '/' : '';
      const next = prompt('New key:', key);
      if(!next || next === key) return;
      try {
        await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/objects/copy?'+new URLSearchParams({key}),
          {method:'POST', body: JSON.stringify({destination_key: next})});
        await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/objects?'+new URLSearchParams({key}), {method:'DELETE'});
        this.toast('Renamed');
        await this.browseBucket(bucket);
      } catch(e){ this.toast(e.message,true); }
    },
    async moveObject(bucket, key){
      const dest = prompt('Move to bucket[/prefix/new-name]:', '');
      if(!dest) return;
      let destBucket = dest, destKey = key;
      if(dest.includes('/')){
        const i = dest.indexOf('/');
        destBucket = dest.substring(0, i); destKey = dest.substring(i+1);
        if(!destKey) destKey = key;
      }
      try {
        await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/objects/copy?'+new URLSearchParams({key}),
          {method:'POST', body: JSON.stringify({destination_bucket: destBucket, destination_key: destKey})});
        await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/objects?'+new URLSearchParams({key}), {method:'DELETE'});
        this.toast('Moved');
        await this.browseBucket(bucket);
        await this.refreshBuckets();
      } catch(e){ this.toast(e.message,true); }
    },
    handleDrop(ev){ this.dropHover = false; this.uploadFiles(this.currentBucket, ev.dataTransfer.files); },
    handleFileInput(ev){ this.uploadFiles(this.currentBucket, ev.target.files); ev.target.value = ''; },
    encEnabled: false,
    encPass: '',
    encKeys(){ try { return JSON.parse(localStorage.getItem('teledrive-enc-keys')||'[]'); } catch(e){ return []; } },
    rememberEncKey(bucket, key){
      const id = bucket + '/' + key;
      const list = this.encKeys();
      if(!list.includes(id)){ list.push(id); localStorage.setItem('teledrive-enc-keys', JSON.stringify(list)); }
    },
    isEncKey(bucket, key){ return this.encKeys().includes(bucket + '/' + key); },
    async uploadFiles(bucket, files){
      const list = Array.from(files||[]);
      if(!list.length) return;
      if(this.encEnabled && !this.encPass){
        this.encPass = prompt('Encryption passphrase for these files (cannot be recovered if lost):') || '';
        if(!this.encPass){ this.toast('Upload cancelled — passphrase required', true); return; }
      }
      // Sequential uploads so progress is visible per file.
      const uploadNext = async (i) => {
        if(i >= list.length){ this.uploading = false; this.browseBucket(bucket).then(()=>this.refreshBuckets()); return; }
        const file = list[i];
        this.uploading = true; this.uploadName = file.name + (this.encEnabled ? ' (encrypting…)' : ''); this.uploadPct = 0;
        try {
          let body = file;
          if(this.encEnabled){
            const plain = new Uint8Array(await file.arrayBuffer());
            body = await TeledriveCrypto.encryptBytes(this.encPass, plain);
            this.uploadName = file.name + ' (encrypted)';
          }
          await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('PUT', this.contentUrl(bucket, file.name));
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');
            xhr.setRequestHeader('X-TeleDrive-CSRF', '1');
            xhr.withCredentials = true;
            xhr.upload.onprogress = (ev) => { if(ev.lengthComputable) this.uploadPct = Math.round(100*ev.loaded/ev.total); };
            xhr.onload = () => (xhr.status === 201) ? resolve() : reject(new Error('Upload failed: ' + (xhr.responseText||xhr.status)));
            xhr.onerror = () => reject(new Error('Upload failed: ' + file.name));
            xhr.send(body);
          });
          if(this.encEnabled) this.rememberEncKey(bucket, file.name);
          this.toast('Uploaded ' + file.name + (this.encEnabled ? ' (encrypted)' : ''));
        } catch(e){ this.toast(e.message, true); }
        uploadNext(i+1);
      };
      uploadNext(0);
    },
    async downloadObject(bucket, key){
      try {
        const r = await fetch(this.contentUrl(bucket, key), {credentials:'include'});
        if(!r.ok) throw new Error('Download failed: ' + r.status);
        const bytes = new Uint8Array(await r.arrayBuffer());
        if(TeledriveCrypto.isEncrypted(bytes)){
          const pass = prompt('This object is client-side encrypted. Passphrase:') || '';
          if(!pass){ this.toast('Download cancelled', true); return; }
          let plain;
          try { plain = await TeledriveCrypto.decryptBytes(pass, bytes); }
          catch(e){ this.toast(e.message, true); return; }
          this.saveBlob(new Blob([plain]), key.split('/').pop() || 'download');
          this.toast('Decrypted and downloaded');
          return;
        }
        this.saveBlob(new Blob([bytes]), key.split('/').pop() || 'download');
      } catch(e){ this.toast(e.message, true); }
    },
    saveBlob(blob, filename){
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(()=>URL.revokeObjectURL(url), 5000);
    },
    async refreshBuckets(){
      try { const r = await this.api('/api/v1/admin/storage/buckets'); this.buckets = r.buckets||[]; }
      catch(e){ this.toast(e.message,true); }
    },
    async createBucket(){
      if(!this.newBucketName.trim()) return;
      try {
        await this.api('/api/v1/admin/storage/buckets',{method:'POST',body:JSON.stringify({name:this.newBucketName.trim()})});
        this.toast('Bucket created');
        this.showNewBucket = false;
        this.newBucketName = '';
        await this.refreshBuckets();
      } catch(e){ this.toast(e.message,true); }
    },
    async deleteBucket(name){
      if(!this.confirmDelete('bucket ' + name, 'Only possible when the bucket is empty.')) return;
      try { await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(name),{method:'DELETE'}); this.toast('Deleted'); await this.refreshBuckets(); if(this.currentBucket===name) this.currentBucket=null; }
      catch(e){ this.toast(e.message,true); }
    },
    async browseBucket(name){
      this.currentBucket = name;
      try { const r = await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(name)+'/objects'); this.bucketObjects = r.objects||[]; }
      catch(e){ this.toast(e.message,true); }
    },
    async deleteObject(bucket,key){
      if(!this.confirmDelete(key, 'Telegram media is retained (physical GC is owner-gated).')) return;
      try { await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/objects?'+new URLSearchParams({key}),{method:'DELETE'}); this.toast('Deleted'); await this.browseBucket(bucket); await this.refreshBuckets(); }
      catch(e){ this.toast(e.message,true); }
    },
    async editQuota(name){
      this.quotaEditBucket = name;
      try {
        const r = await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(name)+'/quota');
        this.quotaMaxSize = r.max_size_bytes||'';
        this.quotaMaxObjects = r.max_objects||'';
      } catch(e){ this.toast(e.message,true); }
    },
    async saveQuota(){
      try {
        const body = {};
        if(this.quotaMaxSize) body.max_size_bytes = Number(this.quotaMaxSize);
        if(this.quotaMaxObjects) body.max_objects = Number(this.quotaMaxObjects);
        await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(this.quotaEditBucket)+'/quota',{method:'PUT',body:JSON.stringify(body)});
        this.toast('Quota saved');
        this.quotaEditBucket = null;
        await this.refreshBuckets();
      } catch(e){ this.toast(e.message,true); }
    },
    toggleLogLive(){
      this.logLive = !this.logLive;
      if(this.logLive){
        this.loadLogs();
        this._startLogStream();
      } else {
        this._stopLogStream();
      }
    },

    _startLogStream(){
      // Live logs over WebSocket; falls back to 3s polling when the
      // socket cannot be established (proxy without WS support).
      this._stopLogStream();
      try {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(proto + '//' + location.host + '/api/v1/logs/stream');
        this._logWs = ws;
        ws.onmessage = (ev)=>{
          // "[ts] [user] [source] message" — same pipeline as loadLogs.
          const m = ev.data.match(/^\[(.+)\] \[(.*)\] \[(.*)\] (.*)$/);
          if(m) this._ingestLogEntries([{ts:m[1], user:m[2], source:m[3], message:m[4]}], true);
        };
        ws.onclose = ()=>{
          if(this.logLive && this._logWs === ws){
            this._logWs = null;
            if(!this._logTimer) this._logTimer = setInterval(()=>this.loadLogs(), 3000);
          }
        };
      } catch(e){
        this._logTimer = setInterval(()=>this.loadLogs(), 3000);
      }
    },

    _stopLogStream(){
      if(this._logWs){ try{ this._logWs.close(); }catch(e){} this._logWs = null; }
      if(this._logTimer){ clearInterval(this._logTimer); this._logTimer=null; }
    },

    _ingestLogEntries(entries, append){
      let list = append ? this.logEntries.concat(entries) : entries;
      this.logHiddenCount = this.logHideNoise
        ? list.filter(e => e.source==='http' && LOG_NOISE_RE.test(e.message)).length : 0;
      if(this.logHideNoise) list = list.filter(e => !(e.source==='http' && LOG_NOISE_RE.test(e.message)));
      const filter = (this.logFilter||'').trim().toLowerCase();
      if(filter) list = list.filter(e => (e.ts+' '+e.user+' '+e.source+' '+e.message).toLowerCase().includes(filter));
      this.logEntries = list.slice(-(this.logLimit||1000));
    },

    async loadUsers(){
      try { const r = await this.api('/api/v1/admin/users'); this.users = r.users||[]; }
      catch(e){ this.toast(e.message,true); }
    },
    async createUser(){
      try {
        const body = {username:this.newUser.username.trim(), password:this.newUser.password, role:this.newUser.role};
        await this.api('/api/v1/admin/users',{method:'POST',body:JSON.stringify(body)});
        this.toast('User created');
        this.showNewUser = false;
        this.newUser = {username:'', password:'', role:'viewer'};
        await this.loadUsers();
      } catch(e){ this.toast(e.message,true); }
    },
    async deleteUser(id){
      if(!this.confirmDelete('this user', 'Their sessions are revoked immediately.')) return;
      try { await this.api('/api/v1/admin/users/'+id,{method:'DELETE'}); this.toast('User deleted'); await this.loadUsers(); }
      catch(e){ this.toast(e.message,true); }
    },
    async changePassword(id){
      const pw = prompt('New password (min 8 chars):');
      if(!pw) return;
      try { await this.api('/api/v1/admin/users/'+id+'/password',{method:'PUT',body:JSON.stringify({password:pw})}); this.toast('Password changed'); }
      catch(e){ this.toast(e.message,true); }
    },
    async changeRole(id, role){
      try { await this.api('/api/v1/admin/users/'+id+'/role',{method:'PUT',body:JSON.stringify({role})}); this.toast('Role updated'); await this.loadUsers(); }
      catch(e){ this.toast(e.message,true); await this.loadUsers(); }
    },

    // ------------------------------------------------------------------
    // S3 governance (/s3/governance). Every call is signed server-side by
    // the router with a real S3 credential; the browser never sees one.
    // ------------------------------------------------------------------
    govBucket: '',
    govTab: 'policy',
    govLoaded: {},
    govBusy: false,
    govError: null,
    govNotice: '',
    govCredentials: [],
    govCredentialId: '',
    govPolicy: {configured:false, text:''},
    govOwnership: {model:'BucketOwnerEnforced', models:['BucketOwnerEnforced','ObjectWriter','BucketOwnerPreferred']},
    govPab: {flags:{BlockPublicAcls:true, IgnorePublicAcls:true, BlockPublicPolicy:true, RestrictPublicBuckets:true}},
    govLock: {enabled:false, mode:'COMPLIANCE', days:30},
    govWebsite: {configured:false, index_document:'index.html', error_document:'', public_read:false, site_url:''},
    govNotify: {configured:false, enabled:false, destination:'', events:[], filter_prefix:'', filter_suffix:'', events_available:[], approved_destinations:[]},
    govReplication: {configured:false, rules:[], destinations:[]},
    govTiering: {configs:[], access_tiers:['ARCHIVE_ACCESS','DEEP_ARCHIVE_ACCESS'], form:null, editing:false},
    govReports: {kinds:['analytics','inventory','metrics'], reports:{analytics:[], inventory:[], metrics:[]}},
    govReportForm: null,
    govTabs: [
      ['policy','Bucket policy'], ['ownership','Ownership'], ['pab','Public access block'],
      ['lock','Object lock'], ['website','Website'], ['notifications','Notifications'],
      ['replication','Replication'], ['tiering','Intelligent-Tiering'], ['reports','Storage reports'],
    ],

    async govInit(){
      await this.refreshBuckets();
      try {
        const r = await this.govCall('/api/v1/admin/s3-governance/signing-credentials');
        this.govCredentials = r.credentials || [];
        if(this.govCredentials.length && !this.govCredentialId){
          this.govCredentialId = this.govCredentials[0].id;
        }
      } catch(e){ /* the page still works; writes report the missing credential */ }
      if(!this.govBucket && this.buckets.length) this.govBucket = this.buckets[0].name;
      if(this.govBucket) await this.govLoad(this.govTab);
    },
    govUrl(suffix){
      return '/api/v1/admin/s3-governance/' + encodeURIComponent(this.govBucket) + suffix;
    },
    govCredentialBody(){
      return this.govCredentialId ? {credential_id:this.govCredentialId} : {};
    },
    async govCall(url, opt={}){
      const headers = {'Content-Type':'application/json','X-TeleDrive-CSRF':'1', ...(opt.headers||{})};
      const r = await fetch(url, {credentials:'include', headers, ...opt});
      const text = await r.text();
      let data = {};
      try { data = text ? JSON.parse(text) : {}; } catch(e){ data = {detail:text}; }
      if(!r.ok){
        const err = new Error(data.code ? (data.code + ': ' + data.message) : (data.detail || r.statusText));
        err.code = data.code || r.headers.get('X-AWS-Error-Code') || null;
        err.awsMessage = data.message || data.detail || r.statusText;
        err.status = r.status;
        throw err;
      }
      return data;
    },
    govFail(e){
      this.govError = {code:e.code, message:e.awsMessage || e.message, status:e.status};
      this.toast(e.message, true);
    },
    async govSelectBucket(){
      this.govLoaded = {};
      this.govError = null;
      this.govNotice = '';
      await this.govLoad(this.govTab);
    },
    async govGo(tab){
      this.govTab = tab;
      this.govError = null;
      if(!this.govLoaded[tab]) await this.govLoad(tab);
    },
    async govLoad(tab){
      if(!this.govBucket) return;
      this.govBusy = true;
      try {
        if(tab === 'policy') await this.loadGovPolicy();
        else if(tab === 'ownership') await this.loadGovOwnership();
        else if(tab === 'pab') await this.loadGovPab();
        else if(tab === 'lock') await this.loadGovLock();
        else if(tab === 'website') await this.loadGovWebsite();
        else if(tab === 'notifications') await this.loadGovNotify();
        else if(tab === 'replication') await this.loadGovReplication();
        else if(tab === 'tiering') await this.loadGovTiering();
        else if(tab === 'reports') await this.loadGovReports();
        this.govLoaded[tab] = true;
      } catch(e){ this.govFail(e); }
      finally { this.govBusy = false; }
    },
    async govMutate(label, fn){
      if(!this.isAdmin){ this.toast('Writes require the admin role', true); return null; }
      this.govBusy = true;
      this.govError = null;
      try {
        const result = await fn();
        this.toast(label);
        return result;
      } catch(e){ this.govFail(e); return null; }
      finally { this.govBusy = false; }
    },

    // 1. bucket policy
    async loadGovPolicy(){
      const r = await this.govCall(this.govUrl('/policy'));
      let text = r.policy || '';
      if(r.configured){
        try { text = JSON.stringify(JSON.parse(text), null, 2); } catch(e){}
      }
      this.govPolicy = {configured:!!r.configured, text:text};
    },
    async saveGovPolicy(){
      let parsed;
      try { parsed = JSON.parse(this.govPolicy.text); }
      catch(e){ this.govError = {code:'MalformedPolicy', message:'Invalid JSON: ' + e.message}; return; }
      const r = await this.govMutate('Bucket policy saved', () => this.govCall(
        this.govUrl('/policy'),
        {method:'PUT', body:JSON.stringify({policy:JSON.stringify(parsed), ...this.govCredentialBody()})}));
      if(r) await this.loadGovPolicy();
    },
    async deleteGovPolicy(){
      if(!confirm('Delete the bucket policy?\n\nAll policy-based Allow/Deny statements stop applying immediately. IAM is not used here; the bucket returns to owner-only access.')) return;
      const r = await this.govMutate('Bucket policy deleted', () => this.govCall(
        this.govUrl('/policy') + (this.govCredentialId ? '?credential_id=' + encodeURIComponent(this.govCredentialId) : ''),
        {method:'DELETE'}));
      if(r) await this.loadGovPolicy();
    },

    // 2. ownership controls
    async loadGovOwnership(){
      const r = await this.govCall(this.govUrl('/ownership'));
      this.govOwnership.model = r.model;
      this.govOwnership.models = r.models || this.govOwnership.models;
    },
    async saveGovOwnership(){
      const r = await this.govMutate('Ownership model saved', () => this.govCall(
        this.govUrl('/ownership'),
        {method:'PUT', body:JSON.stringify({model:this.govOwnership.model, ...this.govCredentialBody()})}));
      if(r) await this.loadGovOwnership();
    },

    // 3. public access block
    async loadGovPab(){
      const r = await this.govCall(this.govUrl('/public-access-block'));
      this.govPab.flags = r.flags;
    },
    async saveGovPab(){
      const off = Object.keys(this.govPab.flags).filter(k => !this.govPab.flags[k]);
      if(off.length && !confirm('Turn OFF: ' + off.join(', ') + '?\n\nThis is a deliberate owner decision. It relaxes the forward-looking guard; TeleDrive still has no anonymous object path, but the stored configuration no longer blocks it.')) return;
      const r = await this.govMutate('Public access block saved', () => this.govCall(
        this.govUrl('/public-access-block'),
        {method:'PUT', body:JSON.stringify({flags:this.govPab.flags, ...this.govCredentialBody()})}));
      if(r) await this.loadGovPab();
    },

    // 4. object lock
    async loadGovLock(){
      const r = await this.govCall(this.govUrl('/object-lock'));
      this.govLock.enabled = !!r.enabled;
      this.govLock.mode = r.mode || 'COMPLIANCE';
      this.govLock.days = r.days || 30;
    },
    async enableGovLock(){
      const word = prompt('Object Lock cannot be disabled once enabled.\n\nEvery new object receives a default retention period; COMPLIANCE retention cannot be shortened or removed even by an admin.\n\nType ENABLE-LOCK to continue:');
      if(word !== 'ENABLE-LOCK'){ if(word !== null) this.toast('Confirmation did not match', true); return; }
      const r = await this.govMutate('Object Lock enabled (one-way)', () => this.govCall(
        this.govUrl('/object-lock'),
        {method:'PUT', body:JSON.stringify({mode:this.govLock.mode, days:Number(this.govLock.days) || null, ...this.govCredentialBody()})}));
      if(r) await this.loadGovLock();
    },

    // 5. website
    async loadGovWebsite(){
      const r = await this.govCall(this.govUrl('/website'));
      this.govWebsite = {
        configured: !!r.configured,
        index_document: r.index_document || 'index.html',
        error_document: r.error_document || '',
        public_read: !!r.public_read,
        site_url: r.site_url || ('/site/' + this.govBucket + '/'),
      };
    },
    async saveGovWebsite(){
      const publicRead = !!this.govWebsite.public_read;
      const body = {
        index_document: this.govWebsite.index_document,
        error_document: this.govWebsite.error_document || null,
        public_read: publicRead,
        ...this.govCredentialBody(),
      };
      if(publicRead){
        const word = prompt('public_read PUBLISHES every current object in this bucket anonymously at ' + this.govWebsite.site_url + '.\n\nAnyone who can reach the app origin can read them with no login and no S3 credential.\n\nType PUBLISH to enable anonymous read:');
        if(word !== 'PUBLISH'){ if(word !== null) this.toast('Confirmation did not match', true); return; }
        body.confirm = word;
      }
      const r = await this.govMutate(publicRead ? 'Website saved — BUCKET IS PUBLIC' : 'Website saved', () => this.govCall(
        this.govUrl('/website'), {method:'PUT', body:JSON.stringify(body)}));
      if(r){
        this.govWebsite.public_read = !!r.public_read;
        this.govNotice = r.notice || '';
        await this.loadGovWebsite();
      }
    },
    async deleteGovWebsite(){
      if(!confirm('Delete the website configuration?\n\nThis also revokes public_read, so /site/' + this.govBucket + '/ stops serving objects.')) return;
      const r = await this.govMutate('Website deleted', () => this.govCall(
        this.govUrl('/website') + (this.govCredentialId ? '?credential_id=' + encodeURIComponent(this.govCredentialId) : ''),
        {method:'DELETE'}));
      if(r) await this.loadGovWebsite();
    },

    // 6. notifications
    async loadGovNotify(){
      const r = await this.govCall(this.govUrl('/notifications'));
      this.govNotify = {
        configured: !!r.configured,
        enabled: !!r.enabled,
        destination: r.destination || '',
        events: r.events || [],
        filter_prefix: r.filter_prefix || '',
        filter_suffix: r.filter_suffix || '',
        events_available: r.events_available || [],
        approved_destinations: r.approved_destinations || [],
      };
    },
    async saveGovNotify(){
      if(this.govNotify.enabled && !this.govNotify.events.length){
        this.govError = {code:'InvalidArgument', message:'Select at least one event'}; return;
      }
      const body = {
        enabled: !!this.govNotify.enabled,
        destination: this.govNotify.destination,
        events: this.govNotify.events,
        filter_prefix: this.govNotify.filter_prefix,
        filter_suffix: this.govNotify.filter_suffix,
        ...this.govCredentialBody(),
      };
      if(!body.enabled && !confirm('Disable notifications for this bucket?\n\nNo webhook deliveries happen until a new configuration is saved.')) return;
      const r = await this.govMutate(body.enabled ? 'Notification configuration saved' : 'Notifications disabled', () => this.govCall(
        this.govUrl('/notifications'), {method:'PUT', body:JSON.stringify(body)}));
      if(r) await this.loadGovNotify();
    },

    // 7. replication
    async loadGovReplication(){
      const r = await this.govCall(this.govUrl('/replication'));
      this.govReplication = {
        configured: !!r.configured,
        rules: (r.rules || []).map(x => ({...x})),
        destinations: r.destinations || [],
      };
    },
    addGovReplicationRule(){
      this.govReplication.rules.push({id:'rule-' + (this.govReplication.rules.length + 1), status:'Enabled', prefix:'', destination:this.govReplication.destinations[0] || ''});
    },
    removeGovReplicationRule(index){ this.govReplication.rules.splice(index, 1); },
    async saveGovReplication(){
      if(!this.govReplication.rules.length){ this.govError = {code:'InvalidRequest', message:'Add at least one rule'}; return; }
      const enabled = this.govReplication.rules.filter(r => r.status === 'Enabled');
      if(enabled.length && !confirm('Save replication rules?\n\nEach enabled prefix maps to the existing Telegram replica engine (one replica copy per chunk). Overlapping enabled prefixes are rejected by the server.')) return;
      const r = await this.govMutate('Replication configuration saved', () => this.govCall(
        this.govUrl('/replication'),
        {method:'PUT', body:JSON.stringify({rules:this.govReplication.rules, ...this.govCredentialBody()})}));
      if(r) await this.loadGovReplication();
    },
    async deleteGovReplication(){
      if(!confirm('Delete the replication configuration?\n\nNew objects stop being copied to a second Telegram account. Existing replica chunks are kept.')) return;
      const r = await this.govMutate('Replication configuration deleted', () => this.govCall(
        this.govUrl('/replication') + (this.govCredentialId ? '?credential_id=' + encodeURIComponent(this.govCredentialId) : ''),
        {method:'DELETE'}));
      if(r) await this.loadGovReplication();
    },

    // 8. Intelligent-Tiering
    async loadGovTiering(){
      const r = await this.govCall(this.govUrl('/tiering'));
      this.govTiering.configs = r.configs || [];
      this.govTiering.access_tiers = r.access_tiers || this.govTiering.access_tiers;
      const first = this.govTiering.configs[0];
      this.govTiering.editing = !!first;
      this.govTiering.form = first ? {
        id: first.id, status: first.status, prefix: first.prefix || '',
        tiers: first.tiers.map(t => ({...t})),
      } : {id:'default', status:'Enabled', prefix:'', tiers:[{days:30, access_tier:'ARCHIVE_ACCESS'}]};
    },
    govTieringNew(){
      this.govTiering.editing = false;
      this.govTiering.form = {id:'default', status:'Enabled', prefix:'', tiers:[{days:30, access_tier:'ARCHIVE_ACCESS'}]};
    },
    govTieringEdit(config){
      this.govTiering.editing = true;
      this.govTiering.form = {id:config.id, status:config.status, prefix:config.prefix || '', tiers:config.tiers.map(t => ({...t}))};
    },
    addGovTierRow(){
      const used = this.govTiering.form.tiers.map(t => t.access_tier);
      const next = this.govTiering.access_tiers.find(t => !used.includes(t)) || 'DEEP_ARCHIVE_ACCESS';
      this.govTiering.form.tiers.push({days:90, access_tier:next});
    },
    removeGovTierRow(index){ this.govTiering.form.tiers.splice(index, 1); },
    async saveGovTiering(){
      const form = this.govTiering.form;
      if(!form || !form.id){ this.govError = {code:'InvalidArgument', message:'Configuration id is required'}; return; }
      const r = await this.govMutate('Tiering configuration saved', () => this.govCall(
        this.govUrl('/tiering/' + encodeURIComponent(form.id)),
        {method:'PUT', body:JSON.stringify({
          status: form.status, prefix: form.prefix,
          tiers: form.tiers.map(t => ({days:Number(t.days), access_tier:t.access_tier})),
          ...this.govCredentialBody()})}));
      if(r){ this.govLoaded.tiering = false; await this.loadGovTiering(); }
    },
    async deleteGovTiering(config){
      if(!confirm('Delete tiering configuration "' + config.id + '"?\n\nObjects already gated as ARCHIVE_ACCESS stay gated until a read/restore cycle; deleting the configuration stops future transitions.')) return;
      const r = await this.govMutate('Tiering configuration deleted', () => this.govCall(
        this.govUrl('/tiering/' + encodeURIComponent(config.id)) + (this.govCredentialId ? '?credential_id=' + encodeURIComponent(this.govCredentialId) : ''),
        {method:'DELETE'}));
      if(r){ this.govLoaded.tiering = false; await this.loadGovTiering(); }
    },

    // 9. storage reports
    async loadGovReports(){
      const r = await this.govCall(this.govUrl('/reports'));
      this.govReports.reports = r.reports || {analytics:[], inventory:[], metrics:[]};
      this.govReports.kinds = r.kinds || this.govReports.kinds;
    },
    govReportNew(kind){
      this.govReportForm = {
        kind: kind, id: kind + '-daily', schedule:'Daily', enabled:true,
        prefix:'', destination:{bucket:this.govBucket, prefix:'', format:'CSV'},
      };
    },
    govReportEdit(kind, config){
      this.govReportForm = {
        kind: kind, id: config.id, schedule: config.schedule || 'Daily',
        enabled: config.enabled !== false, prefix: config.prefix || '',
        destination: {
          bucket: (config.destination && config.destination.bucket) || this.govBucket,
          prefix: (config.destination && config.destination.prefix) || '',
          format: (config.destination && config.destination.format) || 'CSV',
        },
      };
    },
    async saveGovReport(){
      const form = this.govReportForm;
      if(!form || !form.id){ this.govError = {code:'InvalidArgument', message:'Configuration id is required'}; return; }
      const body = {
        schedule: form.schedule, enabled: !!form.enabled, prefix: form.prefix,
        destination: form.kind === 'metrics' ? null : form.destination,
        ...this.govCredentialBody(),
      };
      const r = await this.govMutate('Report configuration saved', () => this.govCall(
        this.govUrl('/reports/' + form.kind + '/' + encodeURIComponent(form.id)),
        {method:'PUT', body:JSON.stringify(body)}));
      if(r){ this.govReportForm = null; this.govLoaded.reports = false; await this.loadGovReports(); }
    },
    async deleteGovReport(kind, config){
      if(!confirm('Delete ' + kind + ' configuration "' + config.id + '"?\n\nScheduled report generation stops. Reports already written to the destination bucket stay there.')) return;
      const r = await this.govMutate('Report configuration deleted', () => this.govCall(
        this.govUrl('/reports/' + kind + '/' + encodeURIComponent(config.id)) + (this.govCredentialId ? '?credential_id=' + encodeURIComponent(this.govCredentialId) : ''),
        {method:'DELETE'}));
      if(r){ this.govLoaded.reports = false; await this.loadGovReports(); }
    },
  }
}
