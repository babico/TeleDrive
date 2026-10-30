// Telegram session, channels, routing, replication, and the settings page.
//
// This is the Alpine fragment for /settings/general and /settings/telegram.
// app.js spreads it into its single x-data object only when the file is
// present (`typeof telegramState === 'function'`), because telegram.js is
// loaded on the pages that can reach these methods and nowhere else.
// buckets.html also loads it: buckets.js editPin() calls
// refreshTgSessionStatus().
//
// Move-only split from app.js: the bodies below are verbatim.
(function (global) {
  'use strict';

  global.telegramState = function () {
    return {
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
    };
  };

  global.telegramMethods = function () {
    return {
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
    };
  };
})(window);
