// S3 bucket browser: buckets, objects, previews, links, shares, pins, CORS.
//
// This is the Alpine fragment for /s3/buckets. app.js spreads it into its
// single x-data object only when the file is present
// (`typeof bucketState === 'function'`), because buckets.js is loaded on the
// pages that can reach these methods and nowhere else.
//
// Move-only split from app.js: the bodies below are verbatim, including the
// historical duplicate `downloadObject` (the async fetch/decrypt definition
// later in this object shadowed the earlier window.open one in app.js, and
// still does). Do not "fix" that here without a separate behaviour change.
(function (global) {
  'use strict';

  global.bucketState = function () {
    return {
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
      searchMode: 'key',
      corsRules: [],
      buckets: [],
      currentBucket: null,
      bucketObjects: [],
      showNewBucket: false,
      newBucketName: '',
      quotaEditBucket: null,
      quotaMaxSize: '',
      quotaMaxObjects: '',
    };
  };

  global.bucketMethods = function () {
    return {
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
        this.toast('Unlinked ' + ok + ' object(s); Telegram media is retained until physical GC');
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
        try { await this.api('/api/v1/admin/storage/buckets/'+encodeURIComponent(bucket)+'/objects?'+new URLSearchParams({key}),{method:'DELETE'}); this.toast('Unlinked; Telegram media is retained until physical GC'); await this.browseBucket(bucket); await this.refreshBuckets(); }
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
    };
  };
})(window);
