function app(){
  return {
    // State
    page: 'dashboard',
    tabs: [
      {id:'dashboard',label:'Dashboard'},
      {id:'queue',label:'Queue'},
      {id:'history',label:'History'},
      {id:'storage',label:'Storage'},
      {id:'settings',label:'Settings'},
      {id:'api-management',label:'API Management'},
      {id:'s3',label:'S3'},
      {id:'logs',label:'Logs'}
    ],
    toastMsg: '',
    toastBad: false,
    authPrompt: null,
    authValue: '',

    // Dashboard
    dashboard: {pending:0,failed:0,uploaded:0,strategy:'-'},
    queueRows: [],
    historyRows: [],

    // Settings
    config: null,
    activeChannelId: '',
    activeChannelLabel: 'Loading...',
    channels: [],
    tgApiId: '',
    tgApiHash: '',
    tgPhone: '',
    tgSessionStatus: 'Not checked',
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
    createdS3: null,

    // Logs
    logEntries: [],
    logFilter: '',
    logLimit: 1000,

    async init(){
      await this.loadSettings();
      await this.refreshChannels();
      await this.refreshTgSessionStatus();
      await this.refreshDashboard();
      setInterval(()=>this.refreshDashboard(), 30000);
    },

    toast(msg, bad=false){
      this.toastMsg = msg;
      this.toastBad = bad;
      setTimeout(()=>{ this.toastMsg = ''; }, 4000);
    },

    async api(url, opt={}){
      const r = await fetch(url, {credentials:'include', headers:{'Content-Type':'application/json','X-TeleDrive-CSRF':'1',...(opt.headers||{})}, ...opt});
      if(!r.ok) throw new Error(await r.text() || r.statusText);
      return r.json();
    },

    fmtTs(v){ if(!v) return '-'; return new Date(v*1000).toLocaleString(); },
    esc(s){ return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); },

    async refreshDashboard(){
      try {
        const r = await this.api('/api/v1/admin/storage/health');
        this.dashboard = {pending: r.pending||0, failed: r.failed||0, uploaded: r.uploaded||0, strategy: r.strategy||'-'};
      } catch(e){}
      try {
        const r = await this.api('/api/v1/admin/storage/jobs?limit=100');
        this.queueRows = r.jobs || [];
      } catch(e){}
    },

    async loadSettings(){
      try {
        const config = await this.api('/api/config');
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
        await this.api('/api/config',{method:'PUT',body:JSON.stringify(c)});
        this.toast('Settings saved');
        await this.refreshDashboard();
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
      const name = prompt('Channel name (display):');
      if(!name) return;
      const cid = prompt('Channel ID or username:');
      if(!cid) return;
      try {
        await this.api('/api/v1/admin/storage/channels',{method:'POST',body:JSON.stringify({name:name.trim(),channel_id:cid.trim(),strategy:this.config?.storage?.strategy||'round_robin',scratch_dir:this.config?.storage?.scratch_dir||'/data/tmp'})});
        this.toast('Channel added');
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
        const r = await this.api('/api/v1/admin/storage/telegram-session');
        if(r.configured && r.session){
          this.tgSessionStatus = 'Authorized: '+r.session.account+' (api_id '+r.session.api_id+'), channel '+(r.session.channel||'-');
        } else {
          this.tgSessionStatus = 'No session configured.';
        }
      } catch(e){ this.tgSessionStatus = 'Error: '+e.message; }
    },

    async sendTgCode(){
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
      } catch(e){ this.toast(e.message,true); }
    },

    async verifyTgCode(){
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
      } catch(e){ this.toast(e.message,true); }
    },

    async runJob(){
      try { await this.api('/api/v1/admin/storage/jobs/run-next',{method:'POST'}); this.toast('Job triggered'); await this.refreshDashboard(); }
      catch(e){ this.toast(e.message,true); }
    },

    async submitAuth(){
      if(!this.authPrompt) return;
      try {
        await this.api('/api/auth',{method:'POST',body:JSON.stringify({account:this.authPrompt.account,kind:this.authPrompt.kind,value:this.authValue})});
        this.authValue=''; this.toast('Auth value submitted');
      } catch(e){ this.toast(e.message,true); }
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
        const x = await this.api('/api/logs?limit='+limit);
        let entries = x.entries||[];
        if(filter) entries = entries.filter(e => (e.ts+' '+e.user+' '+e.source+' '+e.message).toLowerCase().includes(filter));
        this.logEntries = entries;
      } catch(e){ this.toast(e.message,true); }
    }
  }
}
