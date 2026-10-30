// Admin console: dashboard, upload queue, history/versions, physical GC,
// users, API keys, and the log viewer.
//
// This is the Alpine fragment for the admin pages. app.js spreads it into its
// single x-data object only when the file is present
// (`typeof adminState === 'function'`). Pages that must load it before
// app.js: index.html (served at / and /dashboard), queue.html, history.html,
// users.html, logs.html, api-management.html.
//
// Cross-file dependencies (all resolved at call time on the merged object):
//   * this.api() / this.toast() / this.confirmDelete() / isAdmin -> app.js
//   * this.refreshBuckets() -> buckets.js (refreshHistory calls it; only
//     history.html reaches that path, and history.html loads buckets.js)
//   * init() in app.js calls refreshDashboard, refreshGC, loadUsers,
//     loadLogs, refreshKeys, loadPermissionCatalog and refreshHistory, so
//     every page whose route has one of those branches must load this file.
//
// Move-only split from app.js: the bodies below are verbatim.
(function (global) {
  'use strict';

  // UI-side noise filter: the logs page's own polling and status requests
  // would otherwise flood its live view. Everything stays in the log
  // file/buffer; these entries are only hidden from the table.
  const LOG_NOISE_RE = /^GET \/api\/v1\/logs( |$)|^GET \/api\/v1\/admin\/storage\/telegram-session\/floodwait( |$)/;

  global.adminState = function () {
    return {
      // Dashboard / queue / history
      dashboard: {pending:0,failed:0,uploaded:0,alerts:0,strategy:'-'},
      dashAccounts: [],
      usageSeries: [],
      gc: {},
      gcScope: 'revoked',
      gcPreview: [],
      queueRows: [],
      historyRows: [],
      bucketUsage: [],

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
      selectedScopes: ['objects:read','objects:write','objects:delete','buckets:read','buckets:manage'],
      createdKey: null,

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

      // History / versions
      versionRows: [],
      versionBucket: '',
    };
  };

  global.adminMethods = function () {
    return {
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
      usagePct(bytes){
        const max = Math.max(...this.usageSeries.map(d => d.bytes), 1);
        return Math.max(3, Math.round(bytes / max * 100));
      },
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
      async refreshVersions(){
        try {
          const q = this.versionBucket ? ('?bucket=' + encodeURIComponent(this.versionBucket)) : '';
          const r = await this.api('/api/v1/admin/storage/version-history'+q);
          this.versionRows = r.versions||[];
        } catch(e){ this.toast(e.message,true); }
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
    };
  };
})(window);
