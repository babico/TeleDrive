// UI-side noise filter: the logs page's own polling and status requests
// would otherwise flood its live view. Everything stays in the log
// file/buffer; these entries are only hidden from the table.
const LOG_NOISE_RE = /^GET \/api\/v1\/logs( |$)|^GET \/api\/v1\/admin\/storage\/telegram-session\/floodwait( |$)/;

function app(){
  return {
    // S3 credential console state and methods, defined by credentials.js.
    // That file is loaded only on /s3/credentials, so every other page
    // spreads nothing rather than throwing a ReferenceError.
    ...(typeof credentialState === 'function' ? credentialState() : {}),
    ...(typeof credentialMethods === 'function' ? credentialMethods() : {}),
    // S3 bucket browser state and methods, defined by buckets.js.
    // Loaded on /s3/buckets plus the pages whose init() calls refreshBuckets
    // (/history, /s3/governance); other pages spread nothing.
    ...(typeof bucketState === 'function' ? bucketState() : {}),
    ...(typeof bucketMethods === 'function' ? bucketMethods() : {}),
    // Telegram session, channels, routing, replication, and the settings
    // page, defined by telegram.js. Loaded on /settings/general,
    // /settings/telegram, and /s3/buckets (buckets.js editPin calls
    // refreshTgSessionStatus); other pages spread nothing.
    ...(typeof telegramState === 'function' ? telegramState() : {}),
    ...(typeof telegramMethods === 'function' ? telegramMethods() : {}),
    // S3 governance, defined by governance.js. Loaded only on
    // /s3/governance; other pages spread nothing.
    ...(typeof governanceState === 'function' ? governanceState() : {}),
    ...(typeof governanceMethods === 'function' ? governanceMethods() : {}),

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

    // S3 credentials live in credentials.js (credentialState /
    // credentialMethods), including the secret reveal. Nothing here
    // persists a secret: the API response is held in component state only.

    // Logs
    logEntries: [],
    logLive: false,
    _logTimer: null,
    logFilter: '',
    logLimit: 1000,
    logHideNoise: true,
    logHiddenCount: 0,

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
        await this.s3Load();
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

  }
}
