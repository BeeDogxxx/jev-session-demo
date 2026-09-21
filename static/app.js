'use strict';
const $ = id => document.getElementById(id);
let meta, job, selected = 0, busy = false;
const escapeHTML = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const pct = value => (value * 100).toFixed(1);
const riskClass = value => value >= .7 ? 'risk-high' : value >= .3 ? 'risk-mid' : 'risk-low';

function clearResults() {
  if (busy) return;
  job = undefined;
  $('analysis').hidden = true;
  $('empty').hidden = false;
  $('export').disabled = true;
  $('progress').style.width = '0%';
  $('progress-label').textContent = '等待分析';
  for (const id of ['total','high','middle','failed']) $(id).textContent = '—';
}
$('input').oninput = clearResults;
$('policy').oninput = clearResults;

async function api(path, body) {
  const options = body === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)};
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '请求失败');
  return data;
}

function parseInput(text) {
  text = text.trim();
  if (!text) throw new Error('请先粘贴对话，或载入示例。');
  if (text.startsWith('[') || text.startsWith('{')) {
    let parsed;
    try { parsed = JSON.parse(text); } catch { throw new Error('JSON 格式有误，请检查引号、逗号和括号。'); }
    if (Array.isArray(parsed)) {
      if (parsed.length && parsed.every(m => m && typeof m === 'object' && 'role' in m)) return [{id:'S01',messages:parsed}];
      return parsed;
    }
    if (parsed && Array.isArray(parsed.sessions)) return parsed.sessions;
    if (parsed && Array.isArray(parsed.messages)) return [parsed];
    throw new Error('JSON 应为 Session 数组，或含 messages / sessions 的对象。');
  }
  const roles = {'用户':'user','助手':'assistant','系统':'system','工具':'tool','user':'user','assistant':'assistant','system':'system','developer':'developer','tool':'tool'};
  return text.split(/^\s*---\s*$/m).filter(s => s.trim()).map((block, index) => {
    const messages = [];
    for (const line of block.trim().split('\n')) {
      const match = line.match(/^\s*(用户|助手|系统|工具|user|assistant|system|developer|tool)\s*[:：]\s*(.*)$/i);
      if (match) messages.push({role:roles[match[1].toLowerCase()],content:match[2]});
      else if (messages.length) messages[messages.length - 1].content += '\n' + line;
      else if (line.trim()) messages.push({role:'user',content:line});
    }
    return {id:'S' + String(index + 1).padStart(2,'0'),messages};
  });
}

function render() {
  if (!job) return;
  $('empty').hidden = true;
  $('analysis').hidden = false;
  const complete = job.results.filter(r => r?.status === 'complete');
  const errors = job.results.filter(r => r?.status === 'error');
  if (complete.length) {
    $('connection-state').textContent = 'Jev 已连接';
    document.querySelector('.connection').classList.add('connected');
  }
  $('total').textContent = job.total;
  $('high').textContent = complete.filter(r => r.scores.overall_attack >= .7).length;
  $('middle').textContent = complete.filter(r => r.scores.overall_attack >= .3 && r.scores.overall_attack < .7).length;
  $('failed').textContent = errors.length;
  $('progress').style.width = (job.done / job.total * 100) + '%';
  $('progress-label').textContent = job.status === 'running' ? `分析中 ${job.done} / ${job.total}` : `批次结束 · ${complete.length} 成功 / ${errors.length} 失败`;
  $('session-list').innerHTML = job.sessions.map((session, i) => {
    const result = job.results[i];
    let score = '<span class="muted">等待中</span>';
    if (result?.status === 'complete') score = `<span class="${riskClass(result.scores.overall_attack)}">${pct(result.scores.overall_attack)}%</span>`;
    if (result?.status === 'error') score = '<span class="risk-high">失败</span>';
    return `<button class="session-item ${selected === i ? 'active' : ''}" data-index="${i}" aria-pressed="${selected === i}"><div class="row"><span class="sid">${escapeHTML(session.id)}</span>${score}</div><p>${escapeHTML(session.state.target_query)}</p></button>`;
  }).join('');
  document.querySelectorAll('.session-item').forEach(button => button.onclick = () => {selected = Number(button.dataset.index); render();});
  renderDetail();
  $('export').disabled = !job.done;
}

function renderDetail() {
  const session = job.sessions[selected], result = job.results[selected];
  let view = '';
  if (!result) view = '<div class="pending">等待 Jev 返回真实结果…</div>';
  else if (result.status === 'error') view = `<div class="pending failure"><strong>本条未获得评分</strong><br>${escapeHTML(result.error)}<br><small>连接失败不代表低攻击意图。</small></div>`;
  else {
    const probability = result.scores.overall_attack;
    view = `<div class="prob-card"><div class="label">当前 Query · 攻击意图可能性</div><div class="number ${riskClass(probability)}">${pct(probability)}<span>%</span></div><div class="subtitle">${probability >= .7 ? '高可能性区间' : probability >= .3 ? '中间区间 · 建议结合原文查看' : '低可能性区间'} · Jev 独立整体判断</div></div><div class="bars">`;
    for (const dimension of meta.dimensions) {
      const value = result.scores[dimension.id];
      view += `<div class="bar-row"><div class="bar-label"><span>${escapeHTML(dimension.name)}</span><span>${pct(value)}%</span></div><div class="bar-track"><div class="bar-fill ${value >= .7 ? 'high' : value >= .3 ? 'mid' : ''}" style="width:${pct(value)}%"></div></div></div>`;
    }
    view += '</div><p class="hint">各项表示该类意图存在的估计概率，彼此可重叠；不相加，也不代表严重程度。</p>';
  }
  const names = {user:'用户',assistant:'助手',system:'系统（对话原文）',developer:'开发者（对话原文）',tool:'工具'};
  view += '<div class="subheading">对话原文 / 高亮当前判断目标</div><div class="chat">';
  session.messages.forEach((message, index) => {
    view += `<div class="message ${index === session.target_index ? 'target' : ''}"><div class="role">${names[message.role]}${index === session.target_index ? ' · 当前 QUERY' : ''}</div><div class="content">${escapeHTML(message.content)}</div></div>`;
  });
  view += '</div>';
  if (result?.status === 'complete') view += `<div class="meta-note">真实调用 · ${escapeHTML(result.model)} · ${result.elapsed_ms} ms · ${Number(result.usage?.input_tokens) || 0} input tokens${result.attempts > 1 ? ' · 请求 ' + result.attempts + ' 次' : ''}</div>`;
  view += `<details><summary>本次业务边界</summary><p class="hint">${escapeHTML(job.policy)}</p></details>`;
  $('detail').innerHTML = view;
}

function setBusy(value) {
  busy = value;
  $('run').disabled = value;
  $('run').innerHTML = value ? '正在分析… <span>↗</span>' : '开始分析 <span>↗</span>';
  for (const id of ['input','policy','examples','file']) $(id).disabled = value;
}

$('run').onclick = async () => {
  if (busy) return;
  $('input-error').textContent = '';
  try {
    const sessions = parseInput($('input').value);
    if (!sessions.length || sessions.length > 20) throw new Error('一次请导入 1–20 个 Session。');
    setBusy(true);
    const {job_id} = await api('/api/run', {sessions,policy:$('policy').value});
    selected = 0;
    do {
      job = await api('/api/jobs/' + job_id);
      render();
      if (job.status === 'running') await new Promise(resolve => setTimeout(resolve,900));
    } while (job.status === 'running');
  } catch (error) { $('input-error').textContent = error.message; }
  finally { setBusy(false); }
};

$('examples').onclick = async () => {
  try {
    $('input').value = JSON.stringify(await api('/examples.json'), null, 2);
    clearResults();
    $('input-error').textContent = '';
  } catch (error) { $('input-error').textContent = error.message; }
};
$('file').onchange = async event => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 2_000_000) { $('input-error').textContent = '文件不能超过 2 MB。'; return; }
  $('input').value = await file.text();
  clearResults();
  $('input-error').textContent = '';
  event.target.value = '';
};
$('settings-button').onclick = () => $('settings').showModal();
$('save-key').onclick = async () => {
  $('save-key').disabled = true;
  try {
    await api('/api/key', {key:$('key').value.trim()});
    $('key').value = '';
    $('key-status').textContent = '密钥已保存在本机。点击测试连接，确认可用。';
    $('connection-state').textContent = '密钥已配置 · 未验证';
    document.querySelector('.connection').classList.remove('connected');
  } catch (error) { $('key-status').textContent = error.message; }
  finally { $('save-key').disabled = false; }
};
$('check').onclick = async () => {
  $('check').disabled = true;
  $('key-status').textContent = '正在向 TypeSafe 发送测试请求…';
  try {
    const result = await api('/api/check', {});
    $('key-status').textContent = `连接成功 · ${result.model} · ${result.elapsed_ms} ms`;
    $('connection-state').textContent = 'Jev 已连接';
    document.querySelector('.connection').classList.add('connected');
  } catch (error) {
    $('key-status').textContent = error.message;
    $('connection-state').textContent = '连接未通过';
    document.querySelector('.connection').classList.remove('connected');
  } finally { $('check').disabled = false; }
};
$('export').onclick = () => {
  if (!job) return;
  const data = {...job,interpretation:'各维度及整体均为独立 Noul 估计；整体不是平均值。未做本地校准，不等于攻击成功率。',display_thresholds:{low_below:.3,high_at_or_above:.7}};
  const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
  const link = document.createElement('a');link.href = url;link.download = 'jev-session-' + job.id.slice(0,8) + '.json';link.click();
  setTimeout(() => URL.revokeObjectURL(url),1000);
};
api('/api/meta').then(value => {
  meta = value;
  $('policy').value = meta.policy;
  $('connection-state').textContent = meta.key_configured ? '密钥已配置 · 未验证' : '尚未配置密钥';
  $('model-label').textContent = meta.model + ' · ' + meta.prompt_version;
}).catch(error => { $('input-error').textContent = '本地服务不可用：' + error.message; $('run').disabled = true; });
