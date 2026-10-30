// S3 governance: bucket policy, ownership controls, public-access block,
// object lock, website hosting, notifications, replication, Intelligent-Tiering
// and storage reports.
//
// This is the Alpine fragment for /s3/governance. app.js spreads it into its
// single x-data object only when the file is present
// (`typeof governanceState === 'function'`), because only that page can reach
// these methods.
//
// It calls out to two things that stay in app.js / buckets.js:
//   * this.refreshBuckets() and this.buckets  -> buckets.js (loaded first on
//     this page, and on /history and /s3/buckets for other reasons)
//   * this.toast() and the isAdmin getter     -> app.js
//
// Move-only split from app.js: the bodies below are verbatim.
(function (global) {
  'use strict';

  global.governanceState = function () {
    return {
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
    };
  };

  global.governanceMethods = function () {
    return {
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
    };
  };
})(window);
