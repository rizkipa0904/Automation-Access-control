'use strict';
// Lightweight DOM/API simulation: no browser, network, credentials or devices required.
const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
  constructor(tag='div') { this.tagName=tag; this.children=[]; this.value=''; this.textContent=''; this.hidden=false; this.disabled=false; this.open=false; this.checked=false; this.files=[]; }
  append(...xs) { this.children.push(...xs); }
  replaceChildren(...xs) { this.children=[...xs]; }
  setAttribute() {}
  addEventListener() {}
  querySelectorAll() { return []; }
}
const html=fs.readFileSync('static/index.html','utf8'), elements={};
for (const m of html.matchAll(/\bid="([^"]+)"/g)) elements[m[1]]=new Element();
elements.mode.value='shared'; elements.platform.value='cisco';
const projects=[], runs={}, requests=[];
const fetch=async (url,opts={})=>{
  requests.push({url,opts}); let result;
  if(url==='/projects' && opts.method==='POST') { const body=JSON.parse(opts.body); const p={id:`p${projects.length+1}`,name:body.name,runs:[]}; projects.push(p); result={id:p.id}; }
  else if(url==='/projects') result={projects,storage_error:null};
  else if(url==='/runs' && opts.method==='POST') { const body=JSON.parse(opts.body), id=`r${Object.keys(runs).length+1}`; const info={id,project_id:body.project_id,platform:body.platform,started:'2026-01-01',total:body.targets.length,done:false}; projects.find(p=>p.id===body.project_id).runs.push(info); runs[id]={...info,project_name:projects.find(p=>p.id===body.project_id).name,results:[{ip:body.targets[0].ip,port:22,status:'collecting',current_command:'show version',activity:[{type:'command',command:'show version',time:'2026-01-01T12:00:00Z'},{type:'output',command:'show version',text:'filtered output',time:'2026-01-01T12:00:01Z'}],evidence:[{command:'show version',text:'<script>test</script>'}],issues:[]}]}; result={id}; }
  else if(url.startsWith('/runs/')) result=runs[url.split('/')[2]];
  else throw Error('Unexpected request '+url);
  return {ok:true,json:async()=>result};
};
const doc={ getElementById:id=>elements[id], querySelector:()=>({content:'token'}), querySelectorAll:()=>[], createElement:t=>new Element(t) };
const ctx={document:doc,fetch,setInterval:()=>0,setTimeout:()=>0,Blob,URL,console}; vm.createContext(ctx);
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
  const preview=body.children.find(c=>c.className==='evidence-block');
  assert.equal(preview.children[1].textContent,'<script>test</script>');
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
  assert(requests.every(x=>x.opts.headers['X-Session-Token']==='token')); 
  console.log('UI simulation passed: project creation, concurrent scans, switching and sanitized preview.');
})().catch(err=>{console.error(err);process.exitCode=1;});
