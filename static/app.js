'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="session-token"]').content;
let projectId = null, runId = null, polling = false, csvGeneration = 0, currentRun = null, selectedDeviceIndex = 0;
const openDevices = new Set(), approvedKeys = new Set();
const setupStorageKey = 'network-access-review-project-setup-v1';
let projectSetup = {};
try { projectSetup = JSON.parse(localStorage.getItem(setupStorageKey) || '{}') || {}; } catch (_) { projectSetup = {}; }
async function api(path, options = {}) {
  options.headers = {...options.headers, 'X-Session-Token': token};
  const response = await fetch(path, options);
  if (!response.ok) { let e = await response.json(); throw new Error(e.error || 'Request failed'); }
  return response;
}
function post(path, data) { return api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)}); }
function row(values = {}) {
  const tr = document.createElement('tr');
  for (const [name, type, placeholder] of [['ip','text','192.0.2.10'],['port','number','22'],['username','text','Username'],['password','password','Password']]) {
    const td = document.createElement('td'), input = document.createElement('input');
    input.name = name; input.type = type; input.placeholder = placeholder; input.value = values[name] || ''; input.autocomplete = name === 'password' ? 'new-password' : 'off'; td.append(input); tr.append(td);
  }
  const td = document.createElement('td'), b = document.createElement('button'); b.type='button'; b.className='remove'; b.textContent='Remove'; b.onclick=()=>tr.remove(); td.append(b); tr.append(td); $('rows').append(tr);
}
row();
$('platform').onchange = () => { const cisco = $('platform').value === 'cisco'; $('legacy-option').hidden = !cisco; if (!cisco) $('legacy').checked = false; rememberProjectSetup(); };
$('mode').onchange = () => { $('shared').hidden = $('mode').value !== 'shared'; $('individual').hidden = $('mode').value !== 'individual'; rememberProjectSetup(); };
$('legacy').onchange = rememberProjectSetup;
$('add').onclick = () => row();
$('clear').onclick = () => { csvGeneration++; $('csv').value = ''; $('password').value = ''; document.querySelectorAll('#rows input[name=password]').forEach(x => x.value = ''); };
function clearProjectInputs() {
  // Never carry targets or credentials from one project's workspace into another.
  csvGeneration++;
  $('ips').value = ''; $('username').value = ''; $('password').value = '';
  $('rows').replaceChildren(); row(); $('csv').value = '';
  $('platform').value = ''; $('mode').value = 'shared'; $('legacy').checked = false; $('legacy-option').hidden = true;
  $('shared').hidden = false; $('individual').hidden = true;
  $('error').textContent = '';
  applyProjectSetup();
}
function rememberProjectSetup() {
  if (!projectId) return;
  projectSetup[projectId] = {platform:$('platform').value, mode:$('mode').value, legacy:$('legacy').checked};
  try { localStorage.setItem(setupStorageKey, JSON.stringify(projectSetup)); } catch (_) {}
}
function applyProjectSetup() {
  const setup = projectSetup[projectId] || {};
  $('platform').value = setup.platform || '';
  $('mode').value = setup.mode === 'individual' ? 'individual' : 'shared';
  $('legacy').checked = setup.legacy === true && $('platform').value === 'cisco';
  $('legacy-option').hidden = $('platform').value !== 'cisco';
  $('shared').hidden = $('mode').value !== 'shared';
  $('individual').hidden = $('mode').value !== 'individual';
}
function inferProjectSetup(project) {
  if (projectSetup[project.id] || !project.runs.length) return;
  const latest = [...project.runs].reverse()[0];
  projectSetup[project.id] = {platform:latest.platform, mode:'shared', legacy:latest.legacy === true};
}
$('toggle-new-scan').onclick = () => { $('scan-form').hidden = !$('scan-form').hidden; if (!$('scan-form').hidden) $('scan-form').scrollIntoView({behavior:'smooth',block:'start'}); };
function saveBlob(blob, name) { const url=URL.createObjectURL(blob), a=document.createElement('a'); a.href=url; a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000); }
$('template').onclick=()=>saveBlob(new Blob(['ip,port,username,password\n192.0.2.10,22,auditor1,EXAMPLE_PASSWORD_1\n192.0.2.11,,auditor2,EXAMPLE_PASSWORD_2\n'],{type:'text/csv'}),'devices-template.csv');
// RFC-style CSV parser supporting quoted commas, quotes and newlines.
function parseCSV(s) { let rows=[], r=[], v='', q=false, ended=false; for(let i=0;i<s.length;i++){const c=s[i]; if(q){if(c==='"' && s[i+1]==='"'){v+='"';i++;}else if(c==='"'){q=false;ended=true;}else v+=c;}else if(c==='"' && v==='' && !ended)q=true;else if(c===','){r.push(v);v='';ended=false;}else if(c==='\n'||c==='\r'){if(c==='\r'&&s[i+1]==='\n')i++;r.push(v);if(r.some(x=>x!==''))rows.push(r);r=[];v='';ended=false;}else{if(ended)throw Error('Invalid CSV format');v+=c;}}if(q)throw Error('Unclosed quote in CSV');if(v!==''||r.length){r.push(v);rows.push(r);}return rows; }
$('csv').onchange = async event => {
  const generation = ++csvGeneration;
  try {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 1000000) throw Error('CSV is too large (1 MB maximum).');
    const contents = await file.text();
    // A project switch or newer import invalidates the pending file read.
    if (generation !== csvGeneration) return;
    const data = parseCSV(contents.replace(/^\uFEFF/, ''));
    const head = (data.shift() || []).map(x => x.trim().toLowerCase());
    if (head.join(',') !== 'ip,port,username,password') throw Error('CSV header must be ip,port,username,password.');
    if (data.length > 200) throw Error('A maximum of 200 devices is allowed.');
    data.forEach((r,i) => { if (r.length !== 4) throw Error(`CSV row ${i+2} must contain 4 columns.`); });
    $('rows').replaceChildren();
    data.forEach(r => row(Object.fromEntries(head.map((h,j) => [h,r[j]]))));
    $('error').textContent = '';
  } catch (e) {
    if (generation === csvGeneration) $('error').textContent = e.message;
  } finally {
    if (generation === csvGeneration) event.target.value = '';
  }
};
function targets(){if($('mode').value==='shared'){return $('ips').value.split(/\r?\n/).filter(x=>x.trim()).map((line,i)=>{let parts=line.split(',');if(parts.length>2)throw Error(`Row ${i+1}: use IP,port format.`);return {ip:parts[0].trim(),port:(parts[1]||'22').trim(),username:$('username').value,password:$('password').value};});}return [...$('rows').querySelectorAll('tr')].map(tr=>Object.fromEntries([...tr.querySelectorAll('input')].map(x=>[x.name,x.value])));}
const platformName = value => value === 'cisco' ? 'Cisco IOS / IOS XE' : 'Palo Alto PAN-OS';
function node(tag, cls, value) { const el = document.createElement(tag); if (cls) el.className = cls; if (value !== undefined) el.textContent = value; return el; }
function countText(value, singular, plural = `${singular}s`) { return `${value} ${value === 1 ? singular : plural}`; }
function statusText(value) { return ({queued:'Queued',connecting:'Connecting to SSH',collecting:'Connected · collecting',completed:'Completed',partial:'Partial',failed:'Failed',cancelled:'Cancelled',interrupted:'Interrupted after restart',host_key_unknown:'Host key verification required'})[value] || value; }
function issueText(value) {
  const legacy = {
    'Koneksi atau sesi SSH gagal. Periksa jaringan, versi SSH, algoritma dan privilege. Untuk perangkat lawas terpercaya, pertimbangkan opsi kompatibilitas SSH lawas.':'SSH connection or session failed. Check network reachability, SSH version, algorithms, and privileges. For trusted legacy devices, consider enabling legacy SSH compatibility.',
    'Koneksi atau sesi SSH gagal. Periksa jaringan, versi SSH, algoritma dan privilege. Untuk perangkat lawas tepercaya, pertimbangkan opsi kompatibilitas SSH lawas.':'SSH connection or session failed. Check network reachability, SSH version, algorithms, and privileges. For trusted legacy devices, consider enabling legacy SSH compatibility.'
  };
  return legacy[value] || value;
}
function runStatus(done, counts) { if (!done) return 'Running'; if (counts.interrupted) return 'Interrupted'; if (counts.cancelled) return 'Cancelled / partial'; if (counts.failed || counts.partial || counts.host_key_unknown) return 'Completed · needs attention'; return 'Completed'; }
function selectProject(project) {
  if (projectId === project.id) return;
  rememberProjectSetup();
  projectId = project.id;
  inferProjectSetup(project);
  const runs = [...project.runs].reverse();
  runId = (runs.find(r => !r.done) || runs[0] || {}).id || null;
  currentRun = null; openDevices.clear(); clearRun(); clearProjectInputs();
}
$('create-project').onclick = async () => {
  try {
    $('project-error').textContent = '';
    const name = $('project-name').value.trim();
    if (!name) throw Error('Enter a project name.');
    $('create-project').disabled = true;
    rememberProjectSetup();
    const project = await (await post('/projects', {name})).json();
    projectId = project.id; runId = null; currentRun = null; openDevices.clear(); clearRun(); clearProjectInputs();
    $('project-name').value = '';
    $('scan-form').hidden = true;
    await refresh();
  } catch (e) { $('project-error').textContent = e.message; }
  finally { $('create-project').disabled = false; }
};
$('start').onclick = async () => {
  try {
    $('error').textContent = '';
    if (!projectId) throw Error('Create or select a project first.');
    const platform = $('platform').value;
    if (!platform) throw Error('Select a device platform first.');
    const data = targets();
    if (!data.length) throw Error('Enter at least one device.');
    $('start').disabled = true;
    const submittedProject = projectId;
    const result = await (await post('/runs', {project_id:submittedProject, platform, targets:data, legacy:$('legacy').checked})).json();
    if (projectId === submittedProject) { runId = result.id; currentRun = null; selectedDeviceIndex = 0; openDevices.clear(); $('scan-form').hidden = true; }
    await refresh();
  } catch (e) { $('error').textContent = e.message; }
  finally { $('start').disabled = false; }
};
$('cancel').onclick = async () => {
  if (!runId) return;
  try { await post(`/runs/${runId}/cancel`, {}); await refresh(); }
  catch (e) { $('error').textContent = e.message; }
};
$('download').onclick = async () => {
  if (!runId) return;
  const selectedRun = runId;
  try { const r = await api(`/runs/${selectedRun}/xlsx`); saveBlob(await r.blob(), `Access_Review_${selectedRun.slice(0,8)}.xlsx`); }
  catch (e) { $('error').textContent = e.message; }
};
function renderProjects(projects) {
  const list = $('projects'); list.replaceChildren();
  if (!projects.length) list.append(node('p','empty-state','No projects yet. Create one to get started.'));
  for (const project of projects) {
    const b = node('button', 'project-item' + (project.id === projectId ? ' selected' : ''));
    b.type = 'button'; b.setAttribute('aria-pressed', String(project.id === projectId));
    b.append(node('strong', '', project.name), node('span', '', `${countText(project.runs.length, 'scan')} · ${project.runs.filter(r => !r.done).length} running`));
    b.onclick = () => { if (projectId !== project.id) selectProject(project); refresh(); };
    list.append(b);
  }
  const project = projects.find(p => p.id === projectId);
  $('selected-project').textContent = project ? project.name : 'Select a project';
  $('active-project-name').textContent = project ? project.name : 'Select a project in the sidebar';
  const scans = $('scans'); scans.replaceChildren();
  if (!project || !project.runs.length) scans.append(node('p', 'empty-state', project ? 'No scans yet. Use the New scan form.' : 'Select a project to see its scans.'));
  if (project) for (const run of [...project.runs].reverse()) {
    const b = node('button', 'scan-item' + (run.id === runId ? ' selected' : '')); b.type = 'button';
    b.setAttribute('aria-pressed', String(run.id === runId));
    const head = node('div','scan-head'); head.append(node('strong','',platformName(run.platform)), node('span', 'badge', runStatus(run.done, run.counts || {})));
    b.append(head, node('span','scan-meta',`${countText(run.total, 'device')} · ${run.started} · ${run.id.slice(0,8)}`));
    b.onclick = () => { if (runId !== run.id) { runId = run.id; currentRun = null; selectedDeviceIndex = 0; openDevices.clear(); clearRun(); } refresh(); };
    scans.append(b);
  }
}
function timeLabel(value) { return value && value.length >= 19 ? value.slice(11,19) : '--:--:--'; }
function renderDeviceDetail(run, device, index) {
  const panel = node('section','device-detail');
  const title = node('div','detail-heading');
  title.append(node('div','terminal-state',`${device.ip}:${device.port} · ${statusText(device.status)}`), node('span','terminal-live-badge',run.done ? 'Saved activity' : 'LIVE'));
  panel.append(title);
  const activity = device.activity || [];
  const terminal = node('div','terminal-output');
  terminal.setAttribute('aria-label',`Live SSH activity for ${device.ip}`);
  if (!activity.length) terminal.append(node('div','terminal-empty',device.status === 'queued' ? 'Queued; waiting for an SSH worker.' : run.done ? 'No activity transcript is available for this saved scan.' : 'Waiting for live SSH activity.'));
  for (const event of activity) {
    const time = node('span','terminal-time',timeLabel(event.time));
    if (event.type === 'command') { const line=node('div','terminal-entry command'); line.append(time,node('span','terminal-text',event.command)); terminal.append(line); }
    else if (event.type === 'output') { const line=node('div','terminal-entry output'); line.append(time,node('span','terminal-text',`${event.command} · filtered output\n${event.text || '[No approved fields found.]'}`)); terminal.append(line); }
    else if (event.type === 'issue') { const line=node('div','terminal-entry issue'); line.append(time,node('span','terminal-text',`${event.command ? event.command+' · ' : ''}${event.message}`)); terminal.append(line); }
    else { const line=node('div','terminal-entry status'); line.append(time,node('span','terminal-text',event.message || 'Activity update')); terminal.append(line); }
  }
  panel.append(terminal, node('p','terminal-footnote','Commands are shown as they run. Device output appears only after sensitive values are filtered.'));
  const detail = node('div','device-body');
  for (const issue of device.issues || []) detail.append(node('p','issue',`${issue.command ? issue.command+': ' : ''}${issueText(issue.message)}`));
  if (device.host_key) {
    detail.append(node('p','host-warning','Verify this fingerprint through a trusted source before approving it.'),node('p','key',`${device.host_key.type} · ${device.host_key.fingerprint}`));
    const endpoint=device.port===22?device.ip:`[${device.ip}]:${device.port}`, approved=`${run.id}:${endpoint}`;
    const btn=node('button','secondary',approvedKeys.has(approved)?'Verified for this session':'I verified this fingerprint'); btn.disabled=approvedKeys.has(approved);
    btn.onclick=async()=>{try{await post('/approve-key',{run_id:run.id,endpoint,fingerprint:device.host_key.fingerprint});approvedKeys.add(approved);btn.disabled=true;btn.textContent='Verified. Start a new scan for this target.';}catch(e){$('error').textContent=e.message;}}; detail.append(btn);
  }
  const evidence=device.evidence||[];
  detail.append(node('div','preview-heading','FILTERED ACCESS CONTROL EVIDENCE'));
  if (!evidence.length) detail.append(node('p','empty-state','No filtered evidence is available yet.'));
  for (const item of evidence) { const block=node('div','evidence-block'); block.append(node('div','evidence-command',item.command),node('pre','evidence-text',item.text||'No approved fields found.')); detail.append(block); }
  panel.append(detail);
  return panel;
}
function renderRun(run) {
  currentRun = run;
  const counts = run.results.reduce((c,r)=>(c[r.status]=(c[r.status]||0)+1,c),{});
  const inProgress = (counts.queued||0)+(counts.connecting||0)+(counts.collecting||0);
  const failed = (counts.failed||0)+(counts.host_key_unknown||0)+(counts.interrupted||0);
  const done = counts.completed||0;
  $('summary').textContent = `${countText(run.results.length,'device')} · ${runStatus(run.done, counts)} · ${platformName(run.platform)} · started ${run.started}`;
  $('download').disabled = !run.done; $('cancel').disabled = run.done;
  const cards=$('status-cards'); cards.replaceChildren();
  for (const [label,value,cls] of [['Total devices',run.results.length,'total'],['In progress',inProgress,'progress'],['Failed',failed,'failed'],['Done',done,'done']]) {const card=node('div',`status-card ${cls}`);card.append(node('span','',label),node('strong','',String(value)));cards.append(card);}
  const container=$('results'); container.replaceChildren();
  if (!run.results.length) {container.append(node('p','empty-state','No devices are attached to this scan.'));return;}
  run.results.forEach((x,index)=>{
    const wrap=node('div','device-row-wrap'+(index===selectedDeviceIndex?' selected':''));
    const b=node('button','device-row'); b.type='button'; b.setAttribute('aria-pressed',String(index===selectedDeviceIndex));
    const progress=x.current_command ? `SSH connected → ${x.current_command} ${x.status==='completed'?'done':'in progress'}` : x.status==='completed' ? 'SSH connected → access control review done' : statusText(x.status);
    b.append(node('strong','device-address',`${x.ip}:${x.port}`),node('span','device-progress',progress),node('span','badge',statusText(x.status)));
    b.onclick=()=>{selectedDeviceIndex=index;renderRun(run);}; wrap.append(b);
    if(index===selectedDeviceIndex) wrap.append(renderDeviceDetail(run,x,index));
    container.append(wrap);
  });
}
function clearRun() {
  currentRun = null;
  $('summary').textContent = 'Select a project and scan to view device activity.';
  $('results').replaceChildren(); $('status-cards').replaceChildren(); $('download').disabled = true; $('cancel').disabled = true;
}
async function refresh() {
  if (polling) return;
  polling = true;
  try {
    const response = await (await api('/projects')).json();
    const projects = response.projects;
    $('storage-error').textContent = response.storage_error ? 'Local storage issue; recent results may be lost. ' + response.storage_error : '';
    if (!projectId && projects.length) {
      const activeProject = [...projects].reverse().find(p => p.runs.some(r => !r.done));
      const selected = activeProject || projects[projects.length - 1];
      projectId = selected.id;
      inferProjectSetup(selected);
      const selectedRuns = [...selected.runs].reverse();
      runId = (selectedRuns.find(r => !r.done) || selectedRuns[0] || {}).id || null;
      clearProjectInputs();
      if (runId) $('scan-form').hidden = true;
    }
    renderProjects(projects);
    const selectedRunId = runId;
    if (selectedRunId) {
      const run = await (await api(`/runs/${selectedRunId}`)).json();
      if (runId === selectedRunId && projectId === run.project_id) renderRun(run);
    } else { clearRun(); const project=projects.find(p=>p.id===projectId); $('selected-project').textContent=project?project.name:'Select a project'; $('summary').textContent=project?'No scan yet. Create a new scan to start reviewing devices.':'Choose a project to view its access review status.'; }
  } catch (e) { $('error').textContent = e.message; }
  finally { polling = false; }
}
setInterval(refresh, 650);
refresh();
