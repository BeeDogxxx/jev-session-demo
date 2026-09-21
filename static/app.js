'use strict';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pct = value => (value * 100).toFixed(1);
const names = {user:'用户',assistant:'助手',system:'系统 · 原文',developer:'开发者 · 原文',tool:'工具'};
const reviewNames = {attack:'确认攻击意图',benign:'确认正常请求',uncertain:'信息不足 / 待确认'};
let meta, preview, job, selected = 0, busy = false, source = '虚构示例', policy, thresholds;
let loadedRaw, draftSource = '虚构示例';
let reviews = {}, detailSignature = '', currentPage = 'workspace', activeJobId, toastTimer;
const sessions = () => job?.sessions || preview?.sessions || [];
const config = () => job?.thresholds || thresholds || {low:.3,high:.7};
const band = p => p >= config().high ? 'high' : p >= config().low ? 'medium' : 'low';
const colorClass = p => band(p) === 'high' ? 'risk-high' : band(p) === 'medium' ? 'risk-mid' : 'risk-low';
const stats = () => ({complete:job?.results.filter(r => r?.status === 'complete') || [],errors:job?.results.filter(r => r?.status === 'error') || []});
function toast(message) {$('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').hidden = true,3500);}
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  let data; try {data = await response.json();} catch {throw new Error('本地服务返回异常，请检查服务是否运行。');}
  if (!response.ok) throw new Error(data.error || '请求失败');
  return data;
}
function parseInput(text) {
  text = text.trim();
  if (!text) throw new Error('请先粘贴对话，或载入示例。');
  if (text.startsWith('[') || text.startsWith('{')) {
    let parsed; try {parsed = JSON.parse(text);} catch {throw new Error('JSON 格式有误，请检查引号、逗号和括号。');}
    if (Array.isArray(parsed)) return parsed.length && parsed.every(m => m && typeof m === 'object' && 'role' in m) ? [{id:'S01',messages:parsed}] : parsed;
    if (parsed && Array.isArray(parsed.sessions)) return parsed.sessions;
    if (parsed && Array.isArray(parsed.messages)) return [parsed];
    throw new Error('JSON 应为 Session 数组，或包含 messages / sessions 的对象。');
  }
  const roles = {'用户':'user','助手':'assistant','系统':'system','工具':'tool',user:'user',assistant:'assistant',system:'system',developer:'developer',tool:'tool'};
  return text.split(/^\s*---\s*$/m).filter(s => s.trim()).map((block,index) => {
    const messages = [];
    for (const line of block.trim().split('\n')) {
      const m = line.match(/^\s*(用户|助手|系统|工具|user|assistant|system|developer|tool)\s*[:：]\s*(.*)$/i);
      if (m) messages.push({role:roles[m[1].toLowerCase()],content:m[2]});
      else if (messages.length) messages[messages.length-1].content += '\n'+line;
      else if (line.trim()) messages.push({role:'user',content:line});
    }
    return {id:'S'+String(index+1).padStart(2,'0'),messages};
  });
}
function setPage(page) {
  currentPage = page;
  for (const name of ['workspace','standards','report']) $('page-'+name).hidden = name !== page;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active',b.dataset.page === page));
  $('page-name').textContent = {workspace:'分析工作台',standards:'判断标准',report:'分析报告'}[page];
  if (page === 'report') renderReport();
  window.scrollTo({top:0,behavior:'auto'});
}
document.querySelectorAll('[data-page]').forEach(b => b.onclick = () => setPage(b.dataset.page));
$('go-report').onclick = () => setPage('report');
function renderFlow() {
  const loaded = sessions().length > 0, finished = job?.status === 'complete';
  const reviewed = Object.keys(reviews).length;
  const steps = [
    ['会话预检',loaded ? sessions().length+' 条已校验' : '等待导入',loaded?'done':'active'],
    ['边界冻结',job?'已记录配置快照':loaded?'规则已就绪':'等待配置',loaded?'done':''],
    ['多维检测',job ? (finished?'检测已结束':job.done+' / '+job.total+' 已返回') : '等待真实调用',finished?'done':job?'active':''],
    ['证据与分流',finished?(stats().complete.length?'关联与分流已生成':'未获得有效结果'):job?'随结果逐条生成':'等待结果',finished?'done':''],
    ['人工复核',reviewed?reviewed+' 条已记录':'待人工确认',finished?(reviewed === job.total?'done':'active'):'']
  ];
  $('workflow').innerHTML = steps.map((s,i) => `<div class="flow-step ${s[2]}"><span class="flow-number">${s[2]==='done'?'✓':String(i+1).padStart(2,'0')}</span><div><strong>${s[0]}</strong><small>${esc(s[1])}</small></div></div>`).join('');
}
function render() {
  const list = sessions(), {complete,errors} = stats();
  if(complete.length) $('connection-state').textContent='Jev 已连接';
  $('total').textContent = list.length || '—';
  $('total-note').textContent = list.length ? list.reduce((n,s)=>n+s.messages.length,0)+' 条消息参与判断' : '等待导入';
  $('high').textContent = job ? complete.filter(r=>band(r.scores.overall_attack)==='high').length : '—';
  $('review-count').textContent = job ? complete.filter(r=>r.triage.route==='review').length : '—';
  $('reviewed').textContent = job ? Object.keys(reviews).length+'/'+job.total : '—';
  $('failed-note').textContent = job ? complete.length+' 条成功 · '+errors.length+' 条失败' : '未开始调用';
  $('high-note').textContent = '整体估计 ≥ '+Math.round(config().high*100)+'%';
  $('source-label').textContent = '数据来源：'+source;
  $('policy-label').textContent = '规则 '+(job?.rule_version||meta?.rule_version||'—')+(job?' · 配置 '+job.policy_hash:' · 本机预检，不调用模型');
  $('batch-tag').title=job?.id||'';
  $('batch-tag').textContent = job ? '#'+job.id.slice(0,8) : list.length ? '待分析' : '未导入';
  $('batch-progress').textContent = job ? job.status==='running' ? '正在检测 '+job.done+' / '+job.total : '批次结束 · '+complete.length+' 成功 / '+errors.length+' 失败' : list.length ? list.length+' 个 Session 已就绪' : '等待预检';
  $('progress').style.width = job ? job.done/job.total*100+'%' : '0%';
  $('heatmap').innerHTML = list.length ? list.map((s,i) => {
    const r=job?.results[i], p=r?.scores?.overall_attack;
    return `<button class="heat-cell ${p!==undefined?band(p):''} ${selected===i?'active':''}" data-session="${i}" aria-label="查看 ${esc(s.id)}"><span>${esc(s.id)}</span><strong>${p!==undefined?Math.round(p*100)+'%':r?.status==='error'?'×':'—'}</strong><small>${p!==undefined?'意图估计':r?.status==='error'?'调用失败':'待检测'}</small></button>`;
  }).join('') : '<p class="hint">导入对话后，在这里查看整批分布。</p>';
  $('heatmap').querySelectorAll('[data-session]').forEach(b=>b.onclick=()=>selectSession(Number(b.dataset.session),true));
  renderQueue(); renderFlow(); renderDetail();
  $('export-json').disabled = !job?.done; $('export-report').disabled = !job?.done;
  $('run').disabled = busy || !list.length;
  if (currentPage==='report') renderReport();
}
function selectSession(index,resetFilter=false) {
  selected=index; detailSignature='';
  if (resetFilter) {$('filter').value='all';$('search').value='';}
  render();
}
function renderQueue() {
  const list=sessions(), search=$('search').value.toLowerCase(), filter=$('filter').value;
  let indexes=list.map((_,i)=>i).filter(i=> {
    const s=list[i],r=job?.results[i];
    if (search && !(s.id+' '+s.messages.map(m=>m.content).join(' ')).toLowerCase().includes(search)) return false;
    if (filter==='high') return r?.status==='complete' && band(r.scores.overall_attack)==='high';
    if (filter==='review') return r?.triage?.route==='review';
    if (filter==='error') return r?.status==='error';
    if (filter==='unreviewed') return r?.status==='complete' && !reviews[i];
    return true;
  });
  if ($('sort').value==='risk') indexes.sort((a,b)=>(job?.results[b]?.scores?.overall_attack??-1)-(job?.results[a]?.scores?.overall_attack??-1));
  $('queue-count').textContent=indexes.length+'/'+list.length;
  $('session-list').innerHTML=indexes.length ? indexes.map(i=> {
    const s=list[i],r=job?.results[i],p=r?.scores?.overall_attack;
    return `<button class="session-item ${i===selected?'active':''}" data-index="${i}" aria-pressed="${i===selected}"><div class="row"><span class="sid">${esc(s.id)}</span><span class="pill ${p!==undefined?band(p):''}">${p!==undefined?pct(p)+'%':r?.status==='error'?'失败':'待检测'}</span></div><p>${esc(s.state.target_query)}</p><div class="session-meta"><span>目标 T${s.target_index+1} · ${s.messages.length} 条上下文消息</span><span>${reviews[i]?'✓ 已复核':''}</span></div></button>`;
  }).join('') : '<div class="empty-inline" style="padding:20px">没有符合条件的会话</div>';
  $('session-list').querySelectorAll('button').forEach(b=>b.onclick=()=>selectSession(Number(b.dataset.index)));
}
for(const id of ['search','filter','sort']) $(id).addEventListener(id==='search'?'input':'change',renderQueue);
function renderDetail() {
  const s=sessions()[selected],r=job?.results[selected];
  if (!s) {$('detail').innerHTML='<div class="empty-state"><div class="symbol">∴</div><h2>每一次判断，都有上下文</h2><p>导入对话后，从会话队列开始分析。</p></div>';return;}
  const signature=JSON.stringify([selected,r?.status,job?.id,preview?.total]);
  if (signature===detailSignature) return;
  detailSignature=signature;
  let html=`<div class="detail-header"><div><div class="eyebrow">SESSION INVESTIGATION</div><h2>${esc(s.id)} <span class="pill">当前目标 T${s.target_index+1}</span></h2><p>${s.target_index} 条历史消息 · 目标之后 ${s.excluded_future||0} 条消息已排除</p></div><span class="pill ${r?.status==='complete'?'low':''}">${r?.status==='complete'?'真实调用已返回':r?.status==='error'?'调用失败':job?'等待结果':'预检通过'}</span></div><div class="detail-body">`;
  if (!r) html+=`<div class="pending"><h3>${job?'正在等待模型结果':'数据已就绪，等待分析'}</h3><p>${job?'本批次最多 2 条会话并发；结果逐条返回。':'运行后会展示 6 项意图估计、3 项辅助判断，以及用户原文的关联分数。'}<br>当前目标及此前历史将发送到 TypeSafe API。</p></div>`;
  else if (r.status==='error') html+=`<div class="pending error-state"><h3>本条未获得有效评分</h3><p>${esc(r.error)}<br>失败与低概率分开记录，本条不会计入概率统计。</p></div>`;
  else {
    const p=r.scores.overall_attack, b=band(p), radius=54, circumference=2*Math.PI*radius;
    const top=meta.dimensions.filter(d=>r.scores[d.id]>=config().high).sort((a,b)=>r.scores[b.id]-r.scores[a.id]);
    const verdict=b==='high'?'当前请求呈现较强越界信号':b==='medium'?'当前请求需要结合原文复核':'当前请求的越界信号较弱';
    html+=`<div class="probability-block"><div class="gauge ${colorClass(p)}"><svg viewBox="0 0 128 128" aria-hidden="true"><circle class="track" cx="64" cy="64" r="${radius}"/><circle class="value" cx="64" cy="64" r="${radius}" stroke-dasharray="${circumference}" stroke-dashoffset="${circumference*(1-p)}"/></svg><div class="gauge-number"><strong>${pct(p)}<span>%</span></strong><small>攻击意图可能性</small></div></div><div class="verdict"><span class="pill ${b}">${esc(r.triage.label)}</span><h3>${verdict}</h3><p>基于整体概率与分流规则生成的摘要。整体判断独立于六个维度，不做平均。</p><div class="signal-chips">${top.length?top.map(d=>`<span>${esc(d.code)} · ${esc(d.name)}</span>`).join(''):'<span>暂无达到高阈值的细分维度</span>'}</div></div></div>`;
    html+='<div class="section-label">01 / 多维意图画像 <small>存在概率 · 维度可重叠</small></div><div class="dimension-grid">';
    for(const d of meta.dimensions) {
      const v=r.scores[d.id];
      html+=`<div class="dimension-card"><div class="dimension-top"><span class="code">${esc(d.code)}</span><span>${esc(d.name)}</span><strong class="${colorClass(v)}">${Math.round(v*100)}<small>%</small></strong></div><div class="bar-track"><div class="bar-fill ${band(v)}" style="width:${pct(v)}%"></div></div><details><summary>${esc(d.group)} · 查看标准</summary><p>${esc(d.definition)}</p><p>触发：${esc(d.include)}</p><p>排除：${esc(d.exclude)}</p></details></div>`;
    }
    html+='</div><div class="section-label">02 / 辅助判断 <small>辅助复核，不计入加权总分</small></div><div class="checks">';
    for(const c of meta.checks) html+=`<div class="check"><span>${esc(c.name)}</span><strong>${pct(r.scores[c.id])}%</strong></div>`;
    html+='</div>';
    if(r.triage.conflicts.length) html+=`<div class="conflict-note">复核提示：${r.triage.conflicts.map(esc).join('；')}。请结合原文确认。</div>`;
    html+='<div class="section-label">03 / 原文证据关联 <small>点击定位原文</small></div>';
    const ev=r.evidence.filter(e=>e.probability>=config().low).sort((a,b)=>b.probability-a.probability);
    html+='<div class="evidence-list">'+(ev.length ? ev.map(e=>`<button class="evidence" data-evidence="${e.message_index}"><div class="row"><span>T${e.message_index+1} · ${e.message_index===s.target_index?'当前请求':'历史用户消息'}</span><span>关联估计 ${pct(e.probability)}% ↙</span></div><p>${esc(s.messages[e.message_index].content)}</p></button>`).join(''):'<div class="empty-inline">没有原文片段达到关联展示阈值。请继续查看完整上下文。</div>')+'</div>';
    html+=`<p class="explain-note">已对最近 ${r.evidence.length} 条用户消息判断是否支持当前越界意图（最多 8 条）；其余历史仍参与整体分析。关联分数不等于因果归因或模型推理过程。</p>`;
  }
  html+='<div class="section-label">04 / 对话时间线 <small>高亮当前判断目标</small></div><div class="transcript">';
  s.messages.forEach((m,i)=>html+=`<article id="turn-${i}" class="message ${i===s.target_index?'target':''}"><div class="role"><span>T${i+1} · ${names[m.role]}</span><span>${i===s.target_index?'CURRENT QUERY':'CONTEXT'}</span></div><div class="content">${esc(m.content)}</div></article>`);
  html+='</div>';
  if(r?.status==='complete') {
    const rev=reviews[selected];
    html+=`<div class="review-box"><h3>05 / 人工复核记录</h3><p class="explain-note">人工结论与模型结果分开保留，不覆盖原始分数。记录保存在本机服务内存，刷新可恢复；请导出长期保存。</p><div class="review-controls"><select id="review-decision" aria-label="人工复核结论"><option value="">选择人工结论</option>${Object.entries(reviewNames).map(([v,n])=>`<option value="${v}" ${rev?.decision===v?'selected':''}>${n}</option>`).join('')}</select><button id="save-review" class="button secondary">保存复核</button>${rev?'<button id="clear-review" class="text-button">撤销</button>':''}</div><textarea id="review-note" class="review-note" placeholder="记录判定依据、误判原因或需要补充的信息…" aria-label="复核备注" maxlength="2000">${esc(rev?.note||'')}</textarea><p id="review-status" class="review-saved">${rev?'已保存 · '+esc(rev.updated_at):''}</p></div>`;
  }
  html+=`<details class="audit"><summary>查看配置与运行记录</summary><dl><dt>规则版本</dt><dd>${esc(job?.rule_version||meta.rule_version)}</dd><dt>Prompt 版本</dt><dd>${esc(job?.prompt_version||meta.prompt_version)}</dd><dt>实际模型</dt><dd>${esc(r?.model||'尚未返回')}</dd><dt>响应耗时</dt><dd>${r?.elapsed_ms!==undefined?r.elapsed_ms+' ms（含网络与重试）':'—'}</dd><dt>输入用量</dt><dd>${r?.usage?.input_tokens!==undefined?esc(r.usage.input_tokens)+' tokens':'未提供'}</dd><dt>问题数量</dt><dd>${r?.question_count||preview?.question_counts?.[selected]||'—'}</dd><dt>请求次数</dt><dd>${r?.attempts||'—'}</dd><dt>配置指纹</dt><dd>${esc(job?.policy_hash||'运行时生成')}</dd></dl><p>${esc(job?.policy||policy)}</p></details><p class="explain-note">概率未经本场景校准，不代表真实心理、攻击成功率或严重程度。界面只提供分析与复核建议，不执行拦截。</p></div>`;
  $('detail').innerHTML=html;
  $('detail').querySelectorAll('[data-evidence]').forEach(b=>b.onclick=()=>{
    const node=$('turn-'+b.dataset.evidence);node.scrollIntoView({behavior:'smooth',block:'nearest'});node.classList.add('highlight');setTimeout(()=>node.classList.remove('highlight'),1600);
  });
  if($('save-review')) $('save-review').onclick=async()=>{
    const decision=$('review-decision').value;
    if(!decision){$('review-status').textContent='请先选择人工结论。';return;}
    $('save-review').disabled=true;
    try{const saved=await api('/api/jobs/'+job.id+'/review',{session_index:selected,decision,note:$('review-note').value.trim()});reviews=saved.reviews;job.reviews=reviews;detailSignature='';render();toast('人工复核已记录，可在报告中导出');}
    catch(e){$('review-status').textContent=e.message;$('save-review').disabled=false;}
  };
  if($('clear-review')) $('clear-review').onclick=async()=>{
    try{const saved=await api('/api/jobs/'+job.id+'/review',{session_index:selected,decision:'clear'});reviews=saved.reviews;job.reviews=reviews;detailSignature='';render();toast('本条复核记录已撤销');}
    catch(e){$('review-status').textContent=e.message;}
  };

}
function renderStandards() {
  $('principles').innerHTML=meta.principles.map((p,i)=>`<div class="principle"><span>${String(i+1).padStart(2,'0')}</span><div>${esc(p)}</div></div>`).join('');
  $('rules').innerHTML=meta.dimensions.map(d=>`<article class="panel rule-card"><div class="rule-title"><h3>${esc(d.code)} / ${esc(d.name)}</h3><span class="pill">${esc(d.group)}</span></div><p>${esc(d.definition)}</p><dl><dt>触发条件</dt><dd>${esc(d.include)}</dd><dt>排除条件</dt><dd>${esc(d.exclude)}</dd></dl><div class="case positive"><small>触发示例</small>${esc(d.positive)}</div><div class="case"><small>排除示例</small>${esc(d.negative)}</div><p class="explain-note">参照内置虚构样本 ${esc(d.case_ids)} · 示例用于解释规则，不是效果验证集。</p></article>`).join('');
}
function renderReport() {
  if(!job){$('report-content').innerHTML='<div class="panel empty-state"><div class="symbol">▥</div><h2>完成一次分析，生成一份可复核的报告</h2><p>报告包含分布、维度信号、人工结论、失败记录与本次配置。</p></div>';return;}
  const {complete,errors}=stats(), high=complete.filter(r=>band(r.scores.overall_attack)==='high').length;
  const middle=complete.filter(r=>band(r.scores.overall_attack)==='medium').length;
  const low=complete.length-high-middle;
  const reviewed=Object.keys(reviews).length;
  const models=[...new Set(complete.map(r=>r.model).filter(Boolean))].join(', ')||'未返回';
  const avg=complete.length?Math.round(complete.reduce((n,r)=>n+r.elapsed_ms,0)/complete.length):null;
  let html=`<div class="panel report-hero"><div class="row"><div><div class="eyebrow">SESSION SAFETY ASSESSMENT / #${esc(job.id.slice(0,8))}</div><h2>${job.status==='running'?'分析进行中 · 阶段报告':'对话攻击意图分析报告'}</h2><p>生成于 ${esc(job.created_at)} · ${esc(source)}<br>规则 ${esc(job.rule_version)} · Prompt ${esc(job.prompt_version)} · 配置 ${esc(job.policy_hash)}</p></div><span><span class="pill ${job.status==='running'?'medium':'low'}">${job.status==='running'?'部分结果':'批次已结束'}</span><p>${reviewed} / ${job.total} 条已人工复核</p></span></div><div class="report-kpis"><div><strong>${high}</strong><span>高可能性</span></div><div><strong>${middle}</strong><span>中间区间</span></div><div><strong>${low}</strong><span>低可能性</span></div><div><strong>${errors.length}</strong><span>调用失败</span></div></div></div>`;
  html+='<section class="panel"><div class="panel-title"><h2>逐条结果与人工结论</h2><span class="eyebrow">MODEL × HUMAN</span></div><div class="report-table-wrap"><table class="report-table"><thead><tr><th>Session</th><th>整体概率</th><th>分流建议</th><th>最高信号维度</th><th>人工结论</th></tr></thead><tbody>';
  job.sessions.forEach((s,i)=> {
    const r=job.results[i],top=r?.status==='complete'?[...meta.dimensions].sort((a,b)=>r.scores[b.id]-r.scores[a.id])[0]:null;
    html+=`<tr><td><button class="text-button" data-report-session="${i}">${esc(s.id)} ↗</button></td><td>${r?.status==='complete'?`<span class="pill ${band(r.scores.overall_attack)}">${pct(r.scores.overall_attack)}%</span>`:r?.status==='error'?'调用失败':'等待结果'}</td><td>${esc(r?.triage?.label||'—')}</td><td>${top?esc(top.name)+' '+pct(r.scores[top.id])+'%':'—'}</td><td>${esc(reviews[i]?reviewNames[reviews[i].decision]:'未复核')}</td></tr>`;
  });
  html+='</tbody></table></div></section><div class="report-grid"><section class="panel"><div class="eyebrow">SIGNAL COVERAGE</div><h2>细分维度高分分布</h2><ul>';
  html+=meta.dimensions.map(d=>`<li>${esc(d.name)}<span>${complete.filter(r=>r.scores[d.id]>=config().high).length} / ${complete.length}</span></li>`).join('');
  html+=`</ul><p>按本批次高阈值 ${config().high*100}% 统计，仅包含成功返回的样本。维度可重叠，各项数量不相加。</p></section><section class="panel"><div class="eyebrow">RUN METADATA</div><h2>运行与复核记录</h2><ul><li>实际模型<span>${esc(models)}</span></li><li>平均响应耗时<span>${avg===null?'—':avg+' ms'}</span></li><li>本批次成功返回<span>${complete.length} / ${job.total}</span></li><li>分流阈值<span>${config().low*100}% / ${config().high*100}%</span></li><li>人工确认攻击<span>${Object.values(reviews).filter(r=>r.decision==='attack').length}</span></li><li>人工确认正常<span>${Object.values(reviews).filter(r=>r.decision==='benign').length}</span></li></ul><p>响应耗时包含网络和重试。成功返回不代表判断正确；本批次未建立独立真值集，因此不计算准确率。</p></section></div>`;
  html+='<div class="report-grid"><section class="panel"><div class="eyebrow">EXECUTION LOG</div><h2>真实执行记录</h2><ul class="activity">'+(job.events.length?job.events.map(e=>`<li>${esc(job.sessions[e.session_index].id)} · ${e.status==='complete'?'结果返回':'调用失败'}<span>${esc(e.time)}</span></li>`).join(''):'<li>等待模型返回。</li>')+'</ul></section><section class="panel"><div class="eyebrow">REVIEW NOTES</div><h2>人工复核备注</h2>';
  html+=reviewed?Object.entries(reviews).map(([i,r])=>`<p><strong>${esc(job.sessions[i].id)} · ${esc(reviewNames[r.decision])}</strong><br>${esc(r.note||'未填写备注')}</p>`).join(''):'<p>尚未记录人工结论。回到工作台，逐条检查原文和维度结果，再保存复核。</p>';
  html+='</section></div><div class="panel interpretation"><h2>判断范围与局限</h2><p>仅判断当前 Query 的可观察意图，不判断攻击是否成功。各百分比为模型估计；分流和摘要由本地规则生成。原文关联分数是额外判断，不是思维链。人工结论与模型结果分别记录，不能将本批次表现作为生产安全承诺。</p><h3>本次业务边界</h3><p>'+esc(job.policy)+'</p></div>';
  $('report-content').innerHTML=html;
  $('report-content').querySelectorAll('[data-report-session]').forEach(b=>b.onclick=()=>{setPage('workspace');selectSession(Number(b.dataset.reportSession),true);$('detail').scrollIntoView({block:'start',behavior:'smooth'});});
}
function setBusy(value) {
  busy=value;
  for(const id of ['open-import','open-policy','examples','file','clear-input','validate','save-policy','save-key','check']) $(id).disabled=value;
  $('run').textContent=value?'正在分析…':'运行分析 ↗';
  $('run').disabled=value||!sessions().length;
}
function clearJob() {job=undefined;activeJobId=undefined;reviews={};selected=0;detailSignature='';sessionStorage.removeItem('jev-active-job');}
async function validateDraft(close=true) {
  const raw=parseInput($('input').value);
  const data=await api('/api/validate',{sessions:raw,policy,thresholds});
  preview=data;loadedRaw=raw;source=draftSource;clearJob();
  const excluded=data.sessions.reduce((n,s)=>n+s.excluded_future,0);
  const duplicateIds=new Set(data.sessions.map(s=>s.id)).size!==data.total;
  $('preflight').textContent=`校验通过：${data.total} 个 Session，${data.sessions.reduce((n,s)=>n+s.messages.length,0)} 条消息参与判断。\n已排除 ${excluded} 条目标之后的消息；每条调用 ${Math.min(...data.question_counts)}–${Math.max(...data.question_counts)} 个判断问题。${duplicateIds?'\n存在重复 ID，界面按原始序号区分，建议导入时改成唯一 ID。':''}`;
  render();if(close){$('import-dialog').close();toast('会话已预检，点击运行分析开始调用 Jev');}
}
$('open-import').onclick=()=>$('import-dialog').showModal();
$('open-policy').onclick=()=>{$('policy').value=policy;$('low-threshold').value=thresholds.low*100;$('high-threshold').value=thresholds.high*100;$('policy-error').textContent='';$('policy-dialog').showModal();};
$('save-policy').onclick=async()=>{
  const nextPolicy=$('policy').value, nextThresholds={low:Number($('low-threshold').value)/100,high:Number($('high-threshold').value)/100};
  try {
    const existing=loadedRaw || sessions().map(s=>({id:s.id,messages:s.messages,target_index:s.target_index}));
    const data=await api('/api/validate',{sessions:existing.length?existing:['配置校验'],policy:nextPolicy,thresholds:nextThresholds});
    policy=data.policy;thresholds=data.thresholds;
    if(existing.length){preview=data;loadedRaw=raw;source=draftSource;clearJob();}
    $('policy-dialog').close();render();toast('配置已更新，下一次分析将使用新的判断边界');
  }catch(e){$('policy-error').textContent=e.message;}
};
$('validate').onclick=async()=>{ $('input-error').textContent='';$('validate').disabled=true;try{await validateDraft();}catch(e){$('input-error').textContent=e.message;}finally{$('validate').disabled=false;} };
$('input').oninput=()=>{draftSource='手动输入';$('preflight').textContent='输入已修改，尚未载入工作台。';};
$('clear-input').onclick=()=>{$('input').value='';$('input').oninput();};
$('examples').onclick=async()=>{try{$('input').value=JSON.stringify(await api('/examples.json'),null,2);draftSource='12 个自建虚构示例';$('preflight').textContent='示例已载入编辑区，点击预检后应用。';$('input-error').textContent='';}catch(e){$('input-error').textContent=e.message;}};
$('file').onchange=async event=>{const f=event.target.files[0];if(!f)return;try{if(f.size>2_000_000)throw new Error('文件不能超过 2 MB。');$('input').value=await f.text();draftSource='文件：'+f.name;$('preflight').textContent='文件已读取，点击预检后应用。';$('input-error').textContent='';}catch(e){$('input-error').textContent=e.message;}event.target.value='';};
async function pollJob(id) {
  do {job=await api('/api/jobs/'+id);reviews=job.reviews||{};render();if(job.status==='running')await new Promise(r=>setTimeout(r,950));}while(job.status==='running');
  const {complete,errors}=stats();toast(`批次结束：${complete.length} 条成功，${errors.length} 条失败`);
}
$('run').onclick=async()=>{
  if(busy)return;
  $('global-error').textContent='';
  try {
    setBusy(true);
    if(activeJobId && job?.status==='running'){await pollJob(activeJobId);return;}
    if(!preview)throw new Error('请先导入并预检会话。');
    const raw=loadedRaw || preview.sessions.map(s=>({id:s.id,messages:s.messages,target_index:s.target_index}));
    const result=await api('/api/run',{sessions:raw,policy,thresholds,data_source:source});
    reviews={};detailSignature='';activeJobId=result.job_id;
    sessionStorage.setItem('jev-active-job',activeJobId);
    await pollJob(activeJobId);
  }catch(e){$('global-error').textContent=e.message+(activeJobId?' 点击运行可尝试恢复批次结果。':'');}
  finally{setBusy(false);}
};
function downloadReport(format){
  if(!job?.done)return;
  const link=document.createElement('a');link.href='/api/jobs/'+job.id+'/export.'+format;
  link.download='jev-'+job.id.slice(0,8)+'.'+format;document.body.appendChild(link);link.click();link.remove();
}
$('export-json').onclick=()=>downloadReport('json');
$('export-report').onclick=()=>downloadReport('md');
$('settings-button').onclick=()=>$('settings').showModal();
$('quick-settings').onclick=()=>$('settings').showModal();
$('save-key').onclick=async()=>{ $('save-key').disabled=true;try{await api('/api/key',{key:$('key').value.trim()});$('key').value='';$('key-status').textContent='密钥已保存，点击测试连接验证。';$('connection-state').textContent='密钥已配置 · 未验证';}catch(e){$('key-status').textContent=e.message;}finally{$('save-key').disabled=false;} };
$('check').onclick=async()=>{ $('check').disabled=true;$('key-status').textContent='正在发送无害测试请求…';try{const r=await api('/api/check',{});$('key-status').textContent=`连接成功 · ${r.model} · ${r.elapsed_ms} ms`;$('connection-state').textContent='Jev 已连接';}catch(e){$('key-status').textContent=e.message;$('connection-state').textContent='连接未通过';}finally{$('check').disabled=false;} };
async function init(){
  try {
    meta=await api('/api/meta');policy=meta.policy;thresholds=meta.thresholds;
    $('model-label').textContent=meta.model;
    $('connection-state').textContent=meta.key_configured?'密钥已配置 · 未验证':'连接设置 · 未配置';
    renderStandards();
    const remembered=sessionStorage.getItem('jev-active-job');
    if(remembered){try{job=await api('/api/jobs/'+remembered);reviews=job.reviews||{};activeJobId=remembered;policy=job.policy;thresholds=job.thresholds;source=job.data_source||'恢复的批次';preview={sessions:job.sessions,total:job.total};render();if(job.status==='running'){setBusy(true);try{await pollJob(remembered);}finally{setBusy(false);}}return;}catch{clearJob();}}
    $('input').value=JSON.stringify(await api('/examples.json'),null,2);draftSource='12 个自建虚构示例';await validateDraft(false);
  }catch(e){$('global-error').textContent='初始化失败：'+e.message;$('run').disabled=true;}
}
init();
