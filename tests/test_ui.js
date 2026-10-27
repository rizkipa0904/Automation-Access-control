'use strict';
// Lightweight DOM/API simulation: no browser, network, credentials or devices required.
const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
  constructor(tag='div') { this.tagName=tag; this.children=[]; this.value=''; this.textContent=''; this.hidden=false; this.disabled=false; this.open=false; this.checked=false; this.files=[]; this.attributes={}; this.scrollTop=0; this.scrollHeight=1000; this.clientHeight=200; }
  append(...xs) { for (const x of xs) { x.parentElement=this; this.children.push(x); } }
  replaceChildren(...xs) { for (const x of this.children) x.parentElement=null; this.children=[]; this.append(...xs); }
  setAttribute(name,value) { this.attributes[name]=String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  addEventListener() {}
  focus() { doc.activeElement=this; }
  closest(selector) { for (let el=this; el; el=el.parentElement) if (matchesSimple(el,selector)) return el; return null; }
  querySelectorAll(selector) {
    const groups=selector.split(',').map(x=>x.trim());
    const descendants=[]; const visit=el=>{ for (const child of el.children) { descendants.push(child); visit(child); } }; visit(this);
    return descendants.filter(el=>groups.some(group=>{
      const parts=group.split(/\s+/); let cursor=el;
      if (!matchesSimple(cursor,parts.pop())) return false;
      while (parts.length) { const part=parts.pop(); cursor=cursor.parentElement; while (cursor && !matchesSimple(cursor,part)) cursor=cursor.parentElement; if (!cursor) return false; }
      return true;
    }));
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
function matchesSimple(el,selector) {
  const tag=selector.match(/^[a-z][\w-]*/i)?.[0];
  if (tag && el.tagName.toLowerCase()!==tag.toLowerCase()) return false;
  for (const [,cls] of selector.matchAll(/\.([\w-]+)/g)) if (!String(el.className||'').split(/\s+/).includes(cls)) return false;
  for (const [,name,value] of selector.matchAll(/\[([\w-]+)(?:=["']?([^\]"']+)["']?)?\]/g)) { const actual=el.getAttribute(name) ?? el[name] ?? null; if (value===undefined ? actual===null : actual!==value) return false; }
  return true;
}
const html=fs.readFileSync('static/index.html','utf8'), elements={};
for (const m of html.matchAll(/\bid="([^"]+)"/g)) elements[m[1]]=new Element();
elements.mode.value='shared'; elements.platform.value='cisco';
const projects=[], runs={}, requests=[];
let runSequence=0;
let rejectNextRun=false;
const fetch=async (url,opts={})=>{
  requests.push({url,opts}); let result;
  if (rejectNextRun && url==='/runs' && opts.method==='POST') { rejectNextRun=false; return {ok:false,json:async()=>({error:'The project has reached 100 saved scans. Delete a completed scan to continue.'})}; }
  if(url==='/projects' && opts.method==='POST') { const body=JSON.parse(opts.body); const p={id:`p${projects.length+1}`,name:body.name,runs:[]}; projects.push(p); result={id:p.id}; }
  else if(url==='/projects') result={projects,storage_error:null};
  else if(url==='/runs' && opts.method==='POST') { const body=JSON.parse(opts.body), id=`r${++runSequence}`; const info={id,project_id:body.project_id,platform:body.platform,started:'2026-01-01',total:body.targets.length,done:false}; projects.find(p=>p.id===body.project_id).runs.push(info); runs[id]={...info,project_name:projects.find(p=>p.id===body.project_id).name,results:[{ip:body.targets[0].ip,port:22,status:'collecting',current_command:'show version',activity:[{type:'command',command:'show version',time:'2026-01-01T12:00:00Z'},{type:'output',command:'show version',text:'filtered output',time:'2026-01-01T12:00:01Z'}],evidence:[{command:'show version',text:'<script>test</script>'}],issues:[]}]}; result={id}; }
  else if(url.startsWith('/runs/') && opts.method==='DELETE') { const id=url.split('/')[2]; const run=runs[id]; projects.find(p=>p.id===run.project_id).runs=projects.find(p=>p.id===run.project_id).runs.filter(x=>x.id!==id); delete runs[id]; result={ok:true}; }
  else if(url.startsWith('/runs/')) result=runs[url.split('/')[2]];
  else throw Error('Unexpected request '+url);
  return {ok:true,json:async()=>result};
};
const doc={ activeElement:null, getElementById:id=>elements[id], querySelector:selector=>selector==='meta[name="session-token"]'?{content:'token'}:selector.startsWith('#rows ')?elements.rows.querySelector(selector.slice(6)):null, querySelectorAll:selector=>selector.startsWith('#rows ')?elements.rows.querySelectorAll(selector.slice(6)):[], createElement:t=>new Element(t) };
const ctx={document:doc,fetch,setInterval:()=>0,setTimeout:()=>0,Blob,URL,console,confirm:()=>true}; vm.createContext(ctx);
vm.runInContext(fs.readFileSync('static/app.js','utf8'),ctx);
const settle=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
  await settle();
  // The downloaded example must be valid for bulk import and contain placeholders only.
  vm.runInContext('saveBlob = (blob, name) => { globalThis.savedBlob = blob; globalThis.savedName = name; }', ctx);
  elements.template.onclick();
  assert.equal(ctx.savedName, 'devices-template.csv');
  const template = await ctx.savedBlob.text();
  assert.equal(template, 'ip,port,username,password\n192.0.2.10,22,auditor1,EXAMPLE_PASSWORD_1\n192.0.2.11,,auditor2,EXAMPLE_PASSWORD_2\n');
  const parsed = vm.runInContext(`parseCSV(${JSON.stringify(template)})`, ctx);
  assert.equal(parsed.length, 3); assert.equal(parsed[2][1], '');
  elements['project-name'].value='Company A'; await elements['create-project'].onclick();
  elements.platform.value='cisco'; elements.platform.onchange(); elements.ips.value='192.0.2.1'; elements.username.value='audit'; elements.password.value='test'; await elements.start.onclick();
  assert.equal(runs.r1.project_id,'p1'); assert.equal(elements.results.children.length,1);
  const deviceRow=elements.results.children[0], deviceButton=deviceRow.children[0], detail=deviceRow.children[1], terminal=detail.children[1], body=detail.children[3];
  assert.equal(deviceButton.children[1].textContent,'SSH connected → show version in progress');
  assert.equal(elements['status-cards'].children.length,4);
  assert.equal(elements['status-cards'].children[1].children[1].textContent,'1');
  assert(terminal.children.some(line=>line.className==='terminal-entry command' && line.children[1].textContent==='show version'));
  assert(terminal.children.some(line=>line.className==='terminal-entry output' && line.children[1].textContent.includes('filtered output')));
  const checks=body.children[0];
  assert(checks.children.some(check=>check.children[0]?.textContent==='Local configured accounts'));
  assert(checks.children.some(check=>check.children[0]?.textContent==='MFA enforcement' && check.children[1]?.textContent==='Not verified'));
  const preview=body.children.find(c=>c.className==='evidence-block');
  assert.equal(preview.children[1].textContent,'<script>test</script>');
  // Poll updates retain scroll position while an operator reads earlier output.
  const firstTerminal=elements.results.querySelector('.terminal-output');
  firstTerminal.scrollTop=250;
  elements.results.querySelector('.device-row').focus();
  runs.r1.results[0].activity.push({type:'activity',message:'Collecting the next field',time:'2026-01-01T12:00:02Z'});
  await vm.runInContext('refresh()',ctx);
  const readingTerminal=elements.results.querySelector('.terminal-output');
  assert.equal(readingTerminal.scrollTop,250);
  assert.strictEqual(doc.activeElement,elements.results.querySelector('.device-row'));
  const stableRow=elements.results.children[0];
  await vm.runInContext('refresh()',ctx);
  assert.strictEqual(elements.results.children[0],stableRow); // No redraw when data did not change.
  readingTerminal.scrollTop=785;
  runs.r1.results[0].activity.push({type:'activity',message:'Continuing collection',time:'2026-01-01T12:00:03Z'});
  await vm.runInContext('refresh()',ctx);
  assert.equal(elements.results.querySelector('.terminal-output').scrollTop,1000); // Follow new output only near the bottom.
  elements['project-name'].value='Company B'; await elements['create-project'].onclick();
  assert.equal(elements.ips.value, ''); assert.equal(elements.username.value, ''); assert.equal(elements.password.value, ''); assert.equal(elements.platform.value, ''); assert.equal(elements.rows.children.length, 1);
  elements.ips.value='192.0.2.2'; elements.username.value='other'; elements.password.value='other-test';
  elements.platform.value='paloalto'; elements.platform.onchange(); await elements.start.onclick();
  assert.equal(runs.r2.project_id,'p2'); assert.equal(runs.r2.platform,'paloalto');
  assert.equal(projects[0].runs.length,1); assert.equal(projects[1].runs.length,1);
  assert.equal(elements['selected-project'].textContent,'Company B');
  elements.projects.children[0].onclick();
  assert.equal(elements.results.children.length, 0); // Never show prior project's controls while loading.
  assert.equal(elements.cancel.disabled, true);
  await settle();
  assert.equal(elements.ips.value, ''); assert.equal(elements.username.value, ''); assert.equal(elements.password.value, '');
  assert.equal(elements['selected-project'].textContent,'Company A');
  assert.equal(elements.results.children.length, 1); // Most recent active scan is shown on project switch.
  assert.equal(elements.platform.value, 'cisco'); // Per-project setup preference is restored without credentials.
  elements.scans.children[0].onclick(); await settle();
  assert.equal(elements.results.children.length,1);
  // A slow CSV read must never populate credentials in a newly selected project.
  let finishFile;
  const slowFile = new Promise(resolve => { finishFile = resolve; });
  elements.csv.files = [{size: 60, text: () => slowFile}];
  const pendingImport = elements.csv.onchange({target: elements.csv});
  elements.projects.children[1].onclick(); await settle();
  finishFile('ip,port,username,password\n192.0.2.1,22,companyA,secretA\n');
  await pendingImport;
  assert.equal(elements['selected-project'].textContent, 'Company B');
  assert.equal(elements.platform.value, 'paloalto');
  assert.equal(elements.rows.children.length, 1);
  assert.equal(elements.rows.children[0].children[0].children[0].value, '');
  // Clearing credentials must invalidate an in-flight CSV read as well.
  let finishClearFile;
  const clearFile = new Promise(resolve => { finishClearFile = resolve; });
  elements.csv.files = [{size: 60, text: () => clearFile}];
  const pendingClearImport = elements.csv.onchange({target: elements.csv});
  elements.clear.onclick();
  finishClearFile('ip,port,username,password\n192.0.2.1,22,companyA,secretA\n');
  await pendingClearImport;
  assert.equal(elements.rows.children[0].children[0].children[0].value, '');
  assert.equal(vm.runInContext("runStatus(true, {failed: 1})", ctx), 'Completed · needs attention');
  assert.equal(vm.runInContext("runStatus(true, {host_key_unknown: 1})", ctx), 'Completed · needs attention');
  assert.equal(vm.runInContext("statusText('connecting')", ctx), 'Connecting to SSH');
  assert.equal(vm.runInContext("issueText('Koneksi atau sesi SSH gagal. Periksa jaringan, versi SSH, algoritma dan privilege. Untuk perangkat lawas tepercaya, pertimbangkan opsi kompatibilitas SSH lawas.')", ctx), 'SSH connection or session failed. Check network reachability, SSH version, algorithms, and privileges. For trusted legacy devices, consider enabling legacy SSH compatibility.');
  // A completed scan can be rerun with its device list, but never with saved credentials.
  runs.r1.done=true; projects[0].runs[0].done=true;
  runs.r1.results[0].status='partial'; runs.r1.results[0].current_command='show version';
  runs.r1.results.push({ip:'192.0.2.9',port:2222,status:'failed',activity:[],evidence:[],issues:[],accounts:[],facts:[]});
  projects[0].runs[0].total=2;
  elements.projects.children[0].onclick(); await settle();
  assert.equal(elements['status-cards'].children[2].children[0].textContent,'Needs attention');
  assert.equal(elements['status-cards'].children[2].children[1].textContent,'2');
  assert.equal(elements.results.children[0].children[0].children[1].textContent,'Partial evidence collected · review issues');
  assert.equal(elements.results.querySelector('.terminal-live-badge').textContent,'SAVED ACTIVITY');
  vm.runInContext("projectSetup.p1 = {platform:'cisco', mode:'individual', legacy:false}",ctx);
  elements.rerun.onclick();
  assert.equal(elements['scan-form'].hidden,false);
  assert.equal(elements.platform.value,'cisco');
  assert.equal(elements.mode.value,'individual');
  assert.equal(elements.ips.value,'192.0.2.1,22\n192.0.2.9,2222');
  assert.equal(elements.rows.children.length,2);
  assert(elements.rows.querySelectorAll('input[name=username], input[name=password]').every(input=>input.value===''));
  assert.equal(elements['rerun-context'].hidden,false);
  elements.rows.querySelectorAll('tr').forEach((tr,i)=>{ tr.querySelector('input[name=username]').value=`fresh${i}`; tr.querySelector('input[name=password]').value=`new-password${i}`; });
  await elements.start.onclick();
  const fullRerun=JSON.parse(requests.filter(x=>x.url==='/runs' && x.opts.method==='POST').at(-1).opts.body);
  assert.equal(fullRerun.rerun_of,'r1');
  assert.equal(fullRerun.targets.length,2);
  assert.equal(fullRerun.targets[1].port,'2222');
  assert(elements.rows.querySelectorAll('input[name=username], input[name=password]').every(input=>input.value===''));
  elements.scans.children[1].onclick(); await settle(); // Select the original saved scan.
  elements.results.querySelector('.device-rerun').onclick();
  assert.equal(elements.mode.value,'shared');
  assert.equal(elements.ips.value,'192.0.2.1,22');
  assert.equal(elements.username.value,''); assert.equal(elements.password.value,'');
  assert.equal(vm.runInContext('rerunSourceId',ctx),'r1');
  let confirmation=''; ctx.confirm=message=>{confirmation=message;return true;};
  await elements['delete-run'].onclick();
  assert(confirmation.includes('saved scan') && confirmation.includes('report'));
  assert.equal(projects[0].runs.length,1);
  assert.equal(elements['rerun-context'].hidden,true);
  assert.equal(elements['selected-project'].textContent,'Company A');
  rejectNextRun=true;
  elements.platform.value='cisco'; elements.ips.value='192.0.2.1'; elements.username.value='audit'; elements.password.value='fresh';
  await elements.start.onclick();
  assert.equal(elements['scan-form'].hidden,false);
  assert(elements['form-error'].textContent.includes('100 saved scans'));
  elements['project-name'].value='Company C'; await elements['create-project'].onclick();
  elements.platform.value='cisco'; elements.platform.onchange();
  elements.ips.value='192.0.2.44'; elements.username.value='switch-auditor'; elements.password.value='fresh-switch-password';
  await elements.start.onclick();
  assert.equal(runs.r4.platform,'cisco');
  runs.r4.done=true; projects[2].runs[0].done=true; runs.r4.results[0].status='completed';
  runs.r4.results[0].accounts=[{username:'auditor',privilege:'15'}];
  runs.r4.results[0].facts=['aaa authentication login default group radius','radius server primary'];
  runs.r4.results[0].checklist=[{id:'CS-01',area:'Local accounts',status:'Needs review',observation:'One local user observed.',follow_up:'Confirm business owner.',evidence_ids:['CS-E01']}];
  await vm.runInContext('refresh()',ctx);
  const switchChecks=elements.results.querySelector('.access-checks');
  assert(switchChecks.children.some(check=>check.children[0]?.textContent==='Local configured accounts'));
  assert(switchChecks.children.some(check=>check.children[0]?.textContent==='AAA, RADIUS, and TACACS+'));
  const checklistItem=elements.results.querySelector('.checklist-item');
  assert.equal(checklistItem.children[0].children[0].textContent,'CS-01');
  assert.equal(checklistItem.children[0].children[2].textContent,'Needs review');
  checklistItem.open=true; checklistItem.ontoggle();
  checklistItem.children[0].focus();
  runs.r4.results[0].activity.push({type:'activity',message:'Saved',time:'2026-01-01T12:00:04Z'});
  await vm.runInContext('refresh()',ctx);
  assert.equal(elements.results.querySelector('.checklist-item').open,true);
  assert.strictEqual(doc.activeElement,elements.results.querySelector('.checklist-summary'));
  elements.rerun.onclick();
  assert.equal(elements.platform.value,'cisco');
  assert.equal(elements.password.value,'');
  // A run whose revision did not change is not downloaded again.
  const beforeRevisionPolls = requests.filter(x=>x.url==='/runs/r4').length;
  runs.r4.revision = 7; projects[2].runs[0].revision = 7;
  await vm.runInContext('refresh()',ctx);
  const afterFirstRevisionPoll = requests.filter(x=>x.url==='/runs/r4').length;
  await vm.runInContext('refresh()',ctx);
  const afterSecondRevisionPoll = requests.filter(x=>x.url==='/runs/r4').length;
  assert.equal(afterFirstRevisionPoll, beforeRevisionPolls + 1);
  assert.equal(afterSecondRevisionPoll, afterFirstRevisionPoll);
  assert(requests.every(x=>x.opts.headers['X-Session-Token']==='token'));
  console.log('UI simulation passed: projects, reruns, scan deletion, status totals, scroll preservation, and sanitized preview.');
})().catch(err=>{console.error(err);process.exitCode=1;});
