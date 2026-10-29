'use strict';
const $ = selector => document.querySelector(selector);
const number = value => Number(value || 0).toLocaleString();
const percent = value => (Number(value) * 100).toFixed(1) + '%';
const severities = {1: 'High', 2: 'Medium', 3: 'Low', 4: 'Informational'};
let currentAlerts = [], currentRules = {}, modelData = {}, updating = false;
function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function badge(severity) { return el('span', severities[severity], 'badge ' + severities[severity].toLowerCase()); }
async function get(url) { const response = await fetch(url, {cache:'no-store'}); if (!response.ok) throw new Error('Request failed'); return response.json(); }
function view() {
  const name = location.hash.replace('#/','') || 'overview';
  const selected = ['overview','incidents','model'].includes(name) ? name : 'overview';
  for (const item of ['overview','incidents','model']) { $('#view-'+item).hidden = item !== selected; const link = $('[data-view="'+item+'"]'); link.classList.toggle('active', item === selected); if (item === selected) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current'); }
  const titles = {overview:['Overview','Signals, in focus.','Follow traffic patterns, inspect detections, and decide what deserves a closer look.'],incidents:['Incidents','From signal to investigation.','Review grouped detections and the evidence that calls for a response.'],model:['Model card','Understand the score.','Inspect held-out results, class balance, and the limits of this trained model.']};
  $('#breadcrumb').textContent=titles[selected][0]; $('#page-title').textContent=titles[selected][1]; $('#page-description').textContent=titles[selected][2];
}
function showDetail(index) {
  const alert = currentAlerts[index]; if (!alert) return;
  $('#detail-title').textContent = alert.rule_ids.map(id => currentRules[id]?.name || id).join(' + ') || 'Suspicious traffic pattern';
  const content = $('#detail-content'); content.replaceChildren();
  content.append(el('p', alert.src + ':' + alert.sport + ' → ' + alert.dst + ':' + alert.dport + ' / ' + alert.protocol.toUpperCase()));
  content.append(el('p', 'First seen: ' + alert.time + ' · Last seen: ' + alert.last_seen));
  content.append(el('p', 'Detector: ' + alert.detector + ' · Model score: ' + (alert.score === null ? 'Awaiting window score' : Number(alert.score).toFixed(3))));
  const keys=[...alert.rule_ids]; if(alert.ml) keys.push('ML');
  for (const id of keys) { content.append(el('h3', currentRules[id]?.name || id)); content.append(el('p', currentRules[id]?.response || 'Inspect the surrounding activity.')); }
  if (alert.features) { content.append(el('h3','Feature snapshot')); const grid=el('div',undefined,'feature-grid'); alert.features.forEach((value,index)=>grid.append(el('div',(modelData.features?.[index] || 'Feature '+index)+': '+Number(value).toFixed(3)))); content.append(grid); }
  $('#detail').showModal();
}
function renderAlerts(data) {
  currentAlerts=data.alerts; currentRules=data.rules;
  const body=$('#alerts'); body.replaceChildren(); $('#alerts-empty').hidden=data.alerts.length>0;
  data.alerts.forEach((alert,index)=>{ const row=el('tr'); const time=el('td',alert.time.slice(11,19), 'mono'); time.append(el('span',alert.time.slice(0,10),'secondary')); row.append(time);
    const detection=el('td',alert.rule_ids.map(id=>data.rules[id]?.name || id).join(' + ') || 'Suspicious traffic pattern'); detection.append(el('span',alert.protocol.toUpperCase()+' · '+alert.id.slice(0,8),'secondary')); row.append(detection);
    row.append(el('td',alert.src+' → '+alert.dst,'mono')); const severity=el('td'); severity.append(badge(alert.severity)); row.append(severity); const detector=el('td'); detector.append(el('span',alert.detector,'badge detector-badge')); row.append(detector); row.append(el('td',alert.score===null?'—':Number(alert.score).toFixed(3),'mono')); const action=el('td'); const button=el('button','View','inspect'); button.type='button'; button.setAttribute('aria-label','Inspect detection '+(index+1)); button.addEventListener('click',()=>showDetail(index)); action.append(button); row.append(action); body.append(row); });
}
function renderStatus(data) {
  const sensor=data.state.sensor || {}; $('#packet-count').textContent=number(sensor.packets); $('#alert-count').textContent=number(data.events); $('#incident-count').textContent=number(data.incidents); $('#ml-count').textContent=number(sensor.ml_suspicious);
  const status=$('#status'); status.textContent=data.capture_active?'Capture active':data.sensor_stale?'Capture heartbeat stale':sensor.status==='completed'?'Replay complete':sensor.status==='failed'?'Capture failed':sensor.status==='stopped'?'Capture stopped':'Awaiting capture'; status.className='status'+(data.capture_active?' active':data.sensor_stale||sensor.status==='failed'?' stale':'');
  $('#mode-tag').textContent=sensor.mode==='replay'?'OFFLINE REPLAY':'LOCAL LIVE LAB'; $('#capture-mode').textContent=sensor.mode || 'Not started'; $('#model-status').textContent=sensor.model_status || 'Not started'; $('#drops').textContent=number(sensor.queue_dropped)+' / '+number(sensor.flow_dropped); $('#unsupported').textContent=number(sensor.unsupported);
  const warning=$('#model-warning'); warning.hidden=!sensor.model_status || sensor.model_status==='ready'; warning.textContent='ML is unavailable: '+(sensor.model_error || 'check the model artifact')+'. Custom rules continue operating.';
  const timeline=$('#timeline'); timeline.replaceChildren(); const values=data.timeline.length?data.timeline:[{count:0}]; const max=Math.max(1,...values.map(item=>item.count)); for(const item of values){const bar=el('div',undefined,'bar'); bar.style.height=Math.max(2,item.count/max*120)+'px'; bar.title=number(item.count)+' alert windows'+(item.time?' · '+new Date(item.time*1000).toISOString():''); timeline.append(bar);}
  const severity=$('#severity-bars'); severity.replaceChildren(); for(const key of [1,2,3,4]){const row=el('div',undefined,'severity-row'); row.append(el('span',severities[key])); const track=el('div',undefined,'track'),fill=el('div',undefined,'fill'); fill.style.width=(Number(data.severities[key]||0)/Math.max(1,data.events)*100)+'%'; track.append(fill);row.append(track,el('span',number(data.severities[key])));severity.append(row);}
  const sources=$('#sources'); sources.replaceChildren(); if(!data.sources.length)sources.append(el('p','No sources recorded yet.','hint')); for(const source of data.sources){const row=el('div',undefined,'source-row');row.append(el('span',source.src,'mono'),el('span',number(source.count)+' windows')); sources.append(row);}
}
function renderIncidents(data) {
  const body=$('#incidents');body.replaceChildren();$('#incidents-empty').hidden=data.incidents.length>0;
  for(const item of data.incidents){const row=el('tr');row.append(el('td',item.id.slice(0,10),'mono'));const seen=el('td',item.first_seen.replace('T',' ').slice(0,19),'mono');seen.append(el('span',item.last_seen.replace('T',' ').slice(0,19),'secondary'));row.append(seen,el('td',item.src+' → '+item.dst,'mono'),el('td',number(item.count)));const severity=el('td');severity.append(badge(item.severity));row.append(severity,el('td',item.detector));body.append(row);}
}
function renderModel(data) {
  modelData=data; $('#model-version').textContent=data.model_version||'Unavailable';$('#model-schema').textContent=data.schema||'—';$('#model-threshold').textContent=data.threshold===undefined?'—':data.threshold.toFixed(2);$('#model-latency').textContent=data.inference_single_window_ms?data.inference_single_window_ms.median.toFixed(1)+' ms':'—';
  for(const domain of ['public','lab']){const metrics=data.metrics?.results?.[domain+'_test']?.random_forest;const container=$('#'+domain+'-metrics');container.replaceChildren();if(!metrics){container.append(el('p','Evaluation not available.'));continue;}for(const [key,label] of [['precision','Precision'],['recall','Recall'],['f1','F1'],['false_positive_rate','False-positive rate']]){const item=el('div');item.append(el('strong',percent(metrics[key])),el('span',label));container.append(item);}}
  const baseline=$('#baseline-results');baseline.replaceChildren();for(const domain of ['public','lab']){const evaluation=data.metrics?.results?.[domain+'_test'];if(evaluation)baseline.append(el('p',domain.toUpperCase()+': '+number(evaluation.random_forest.benign)+' benign / '+number(evaluation.random_forest.suspicious)+' suspicious windows. Majority baseline F1 '+percent(evaluation.majority_baseline.f1)+', false-positive rate '+percent(evaluation.majority_baseline.false_positive_rate)+'.'));}
  const features=$('#feature-importance');features.replaceChildren();for(const [name,importance] of Object.entries(data.feature_importances||{}).sort((a,b)=>b[1]-a[1]).slice(0,6)){const row=el('div',undefined,'importance-row');row.append(el('span',name,'mono'));const track=el('div',undefined,'track'),fill=el('div',undefined,'fill');fill.style.width=percent(importance);track.append(fill);row.append(track,el('span',percent(importance)));features.append(row);}
}
async function update(){if(updating)return;updating=true;try{const query=new URLSearchParams(new FormData($('#filters')));const [status,alerts,incidents]=await Promise.all([get('/api/status'),get('/api/alerts?'+query),get('/api/incidents')]);renderStatus(status);renderAlerts(alerts);renderIncidents(incidents);$('#connection-error').hidden=true;}catch(_error){$('#connection-error').hidden=false;}finally{updating=false;}}
$('#filters').addEventListener('submit',event=>event.preventDefault());$('#filters').addEventListener('change',update);let debounce;$('#filters').addEventListener('input',()=>{clearTimeout(debounce);debounce=setTimeout(update,250);});$('#filters').addEventListener('reset',()=>setTimeout(update,0));$('#close-detail').addEventListener('click',()=>$('#detail').close());window.addEventListener('hashchange',view);view();get('/api/model').then(renderModel).catch(()=>{});update();setInterval(update,2000);
