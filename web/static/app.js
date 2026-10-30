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
    // Admin console (dashboard, queue, history, GC, users, API keys, logs),
    // defined by admin.js. Loaded on index.html, queue.html, history.html,
    // users.html, logs.html and api-management.html; other pages spread
    // nothing.
    ...(typeof adminState === 'function' ? adminState() : {}),
    ...(typeof adminMethods === 'function' ? adminMethods() : {}),

    // State
    toastMsg: '',
    toastBad: false,
    currentUser: '',
    currentRole: '',
    loginUsername: '',
    loginPassword: '',
    loginError: '',

    mustChangePassword: false,

    // Date/key formatters used by more than one admin fragment: fmtRel() and
    // keyExpired() are called by api-management.html and keyExpired() also by
    // credentials.html, which does not load admin.js. They stay here.
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

    // S3 credentials live in credentials.js (credentialState /
    // credentialMethods), including the secret reveal. Nothing here
    // persists a secret: the API response is held in component state only.

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

    async copyText(t){
      try{ await navigator.clipboard.writeText(t); this.toast('Copied'); }catch(e){ this.toast('Clipboard unavailable',true); }
    },

    fmtBytes(b){ if(b==null) return '-'; if(b<1024) return b+' B'; if(b<1048576) return (b/1024).toFixed(1)+' KB'; if(b<1073741824) return (b/1048576).toFixed(1)+' MB'; return (b/1073741824).toFixed(2)+' GB'; },
    quotaPct(used, max){ if(!max) return 0; return Math.min(100, Math.round(100*used/max)); },
  }
}
