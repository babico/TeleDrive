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
    dashboard: {pending:0,failed:0,uploaded:0,strategy:'-'},
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
    keyScopesList: ['objects:read','objects:write','objects:delete','buckets:read','buckets:manage','jobs:read','jobs:manage','accounts:read','accounts:manage','settings:read','settings:manage','keys:manage','admin:*'],
    selectedScopes: ['objects:read','objects:write','objects:delete','buckets:read','buckets:manage'],
    createdKey: null,

    // S3
    s3KeyName: '',
    s3KeyExpiry: '',
    s3Perms: ['s3:ListAllMyBuckets','s3:ListBucket','s3:GetBucketLocation','s3:GetObject','s3:GetObjectAttributes','s3:GetObjectTagging','s3:PutObjectTagging','s3:DeleteObjectTagging','s3:GetBucketTagging','s3:GetBucketCORS','s3:PutBucketCORS','s3:PutBucketTagging','s3:DeleteBucketTagging','s3:PutObject','s3:DeleteObject','s3:CreateBucket','s3:DeleteBucket'],
    selectedS3Perms: ['s3:ListAllMyBuckets','s3:ListBucket','s3:GetBucketLocation','s3:GetObject','s3:PutObject','s3:DeleteObject'],
    s3Keys: [],
    s3Edit: null,
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
      } else if(path === '/s3/credentials'){
        await this.refreshS3Keys();
      } else if(path === '/users'){
        await this.loadUsers();
      } else if(path === '/logs'){
        await this.loadLogs();
      } else if(path === '/api-management'){
        await this.refreshKeys();
      } else if(path === '/history'){
        await this.refreshHistory();
      }
    },

    navActive(p){ return window.location.pathname === p; },

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
          strategy: this.dashboard.strategy
        };
      } catch(e){}
      try {
        const a = await this.api('/api/v1/admin/storage/active-channel');
        this.dashboard.strategy = (a.active && a.active.strategy) || '-';
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
      if(!confirm('Remove this channel?')) return;
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
        if(this.newKeyExpiry) body.expires_at = Math.floor(new Date(this.newKeyExpiry).getTime()/1000);
        const r = await this.api('/api/v1/admin/keys',{method:'POST',body:JSON.stringify(body)});
        this.createdKey = {prefix:r.prefix, token:r.token};
        this.toast('Key created');
        await this.refreshKeys();
      } catch(e){ this.toast(e.message,true); }
    },

    async revokeKey(id){
      if(!confirm('Revoke this key?')) return;
      try { await this.api('/api/v1/admin/keys/'+id,{method:'DELETE'}); this.toast('Revoked'); await this.refreshKeys(); }
      catch(e){ this.toast(e.message,true); }
    },

    async copyText(t){
      try{ await navigator.clipboard.writeText(t); this.toast('Copied'); }catch(e){ this.toast('Clipboard unavailable',true); }
    },

    async revokeS3Key(id){
      if(!confirm('Revoke this S3 key?')) return;
      try { await this.api('/api/v1/admin/s3-credentials/'+id,{method:'DELETE'}); this.toast('Revoked'); await this.refreshS3Keys(); }
      catch(e){ this.toast(e.message,true); }
    },

    startS3Edit(k){
      this.s3Edit = {id: k.id, access_key: k.access_key, name: k.name,
                     permissions: [...(k.permissions||[])]};
    },
    async saveS3Edit(){
      try {
        await this.api('/api/v1/admin/s3-credentials/'+this.s3Edit.id,
          {method:'PUT', body: JSON.stringify({name: this.s3Edit.name.trim(),
            permissions: this.s3Edit.permissions})});
        this.toast('Credential updated');
        this.s3Edit = null;
        await this.refreshS3Keys();
      } catch(e){ this.toast(e.message,true); }
    },
    async refreshS3Keys(){
      try { const r = await this.api('/api/v1/admin/s3-credentials'); this.s3Keys = r.credentials||[]; }
      catch(e){ this.toast(e.message,true); }
    },

    async createS3Key(){
      try {
        const body = {name:this.s3KeyName.trim()||'s3-key', permissions:this.selectedS3Perms.slice()};
        if(this.s3KeyExpiry) body.expires_at = Math.floor(new Date(this.s3KeyExpiry).getTime()/1000);
        const r = await this.api('/api/v1/admin/s3-credentials',{method:'POST',body:JSON.stringify(body)});
        this.createdS3 = {access:r.access_key, secret:r.secret_key};
        this.toast('S3 credentials created');
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
        const r = await this.api('/api/v1/admin/storage/search?q='+encodeURIComponent(q));
        this.searchResults = r.objects||[];
        if(!this.searchResults.length) this.toast('No objects matched');
      } catch(e){ this.toast(e.message,true); }
    },
    syncSelectedKeys(){ this.selectedKeys = new Set(this.selectedKeyList); },
    async deleteSelected(){
      if(!this.selectedKeys.size || !confirm('Delete ' + this.selectedKeys.size + ' object(s)? Telegram media is retained.')) return;
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
    uploadFiles(bucket, files){
      const list = Array.from(files||[]);
      if(!list.length) return;
      // Sequential XHR uploads so progress is visible per file.
      const uploadNext = (i) => {
        if(i >= list.length){ this.uploading = false; this.browseBucket(bucket).then(()=>this.refreshBuckets()); return; }
        const file = list[i];
        this.uploading = true; this.uploadName = file.name; this.uploadPct = 0;
        const xhr = new XMLHttpRequest();
        xhr.open('PUT', this.contentUrl(bucket, file.name));
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        xhr.setRequestHeader('X-TeleDrive-CSRF', '1');
        xhr.withCredentials = true;
        xhr.upload.onprogress = (ev) => { if(ev.lengthComputable) this.uploadPct = Math.round(100*ev.loaded/ev.total); };
        xhr.onload = () => {
          if(xhr.status === 201){ this.toast('Uploaded ' + file.name); }
          else { this.toast('Upload failed: ' + (xhr.responseText||xhr.status), true); }
          uploadNext(i+1);
        };
        xhr.onerror = () => { this.toast('Upload failed: ' + file.name, true); uploadNext(i+1); };
        xhr.send(file);
      };
      uploadNext(0);
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
      if(!confirm('Delete bucket '+name+'? (must be empty)')) return;
      try { await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(name),{method:'DELETE'}); this.toast('Deleted'); await this.refreshBuckets(); if(this.currentBucket===name) this.currentBucket=null; }
      catch(e){ this.toast(e.message,true); }
    },
    async browseBucket(name){
      this.currentBucket = name;
      try { const r = await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(name)+'/objects'); this.bucketObjects = r.objects||[]; }
      catch(e){ this.toast(e.message,true); }
    },
    async deleteObject(bucket,key){
      if(!confirm('Delete '+key+'?')) return;
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
        this._logTimer = setInterval(()=>this.loadLogs(), 3000);
      } else {
        if(this._logTimer){ clearInterval(this._logTimer); this._logTimer=null; }
      }
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
      if(!confirm('Delete this user?')) return;
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
