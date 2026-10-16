(() => {
  let rows = [], active = -1, selectedThreatTypes = new Set(), realAttackThreats = new Set();
  const $ = id => document.getElementById(id);
  const aliases = { threatType:['rule_category_name','rulecategoryname','threat_type','threattype','attack_type','attacktype','category','威胁类型','威胁类别','规则分类'], alertName:['alert_name','alarm_name','alert','alarm','event_name','rule_name','name','告警名称','告警名'], srcIp:['src_ip','source_ip','sourceip','sip','client_ip','clientip','remote_addr','remote_ip','srcip','attacker_content','attackerContent','attacker','源ip','源_ip','攻击者'], srcPort:['src_port','source_port','sourceport','sport','client_port','源端口'], dstIp:['dst_ip','dest_ip','destination_ip','dstip','dip','server_ip','victim_content','victimContent','victim','目的ip','目的_ip','受害者'], dstPort:['dst_port','dest_port','destination_port','dport','server_port','目的端口'], method:['method','http_method','httpmethod','请求方法'], host:['host','http_host','domain','域名'], uri:['uri','url','path','request_uri','uripath','uri_path','请求uri'], reqHeaders:['request_headers','req_headers','http_request_headers','请求头'], reqBody:['request_body','req_body','http_request_body','http_parameter','httpparameter','sql','request_params','request_parameters','参数','请求体','http参数','sql参数'], status:['status','status_code','response_status','http_rsp_code','httprspcode','响应状态','响应码'], resHeaders:['response_headers','res_headers','http_response_headers','响应头'], request:['request','raw_request','http_request','原始请求'], response:['response','raw_response','http_response','原始响应'], time:['timestamp','time','datetime','latesttimestamp','时间'] };
  const norm = v => String(v ?? '').trim();
  const repairMojibake = value => { const text=norm(value); if(!text || !/[\u0080-\u00ff�]/.test(text)) return text; try { const bytes=Uint8Array.from([...text], c=>c.charCodeAt(0)); const fixed=new TextDecoder('gb18030').decode(bytes); return fixed.includes('�') ? text : fixed; } catch { return text; } };
  const keyMap = o => { const m={}; Object.keys(o).forEach(k=>m[k.toLowerCase().replace(/[\s\-]/g,'_')]=o[k]); return m; };
  const get = (o, names) => { const m=keyMap(o); for(const n of names) if(m[n] !== undefined && norm(m[n])) return norm(m[n]); return ''; };
  const unquote = s => { s=norm(s); if(s.length>1 && s[0]=='"' && s.at(-1)=='"') return s.slice(1,-1).replace(/""/g,'"'); return s; };
  const b64ToUtf8 = value => { try { const raw=atob(value.replace(/\s/g,'')); const bytes=Uint8Array.from(raw,c=>c.charCodeAt(0)); return new TextDecoder('utf-8',{fatal:true}).decode(bytes); } catch { return ''; } };
  const maybeDecodeBase64 = value => { const text=norm(value); if(!text || text.length<16 || text.length%4!==0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return ''; const decoded=b64ToUtf8(text); return decoded && /[\u0009\u000a\u000d\u0020-\u007e\u4e00-\u9fff]/.test(decoded) ? decoded : ''; };
  const isAbsoluteUrl = value => /^https?:\/\//i.test(norm(value));
  function parseCSV(text){
    const out=[]; let row=[], cell='', quoted=false;
    for(let i=0;i<text.length;i++){ const c=text[i], n=text[i+1]; if(c==='"'){ if(quoted&&n==='"'){cell+='"';i++;} else quoted=!quoted; } else if(c===','&&!quoted){row.push(cell);cell='';} else if((c==='\n'||c==='\r')&&!quoted){ if(c==='\r'&&n==='\n') i++; row.push(cell); if(row.some(x=>x.trim())) out.push(row); row=[];cell=''; } else cell+=c; }
    row.push(cell); if(row.some(x=>x.trim())) out.push(row); const headers=(out.shift()||[]).map(h=>h.trim()); return out.map(r=>Object.fromEntries(headers.map((h,i)=>[h,repairMojibake(r[i]||'')])));
  }
  async function readCsvFile(file){
    const buffer=await file.arrayBuffer(); const utf8=new TextDecoder('utf-8').decode(buffer); const text=/�/.test(utf8)?new TextDecoder('gb18030').decode(buffer):utf8; return parseCSV(text);
  }
  function parseRaw(raw, isRequest){
    raw=unquote(raw).replace(/\\r\\n/g,'\r\n').replace(/\\n/g,'\n'); if(!raw) return {start:'',headers:'',body:''}; const split=raw.search(/\r?\n\r?\n/); const head=split<0?raw:raw.slice(0,split); const body=split<0?'':raw.slice(split).replace(/^\r?\n\r?\n/,''); const lines=head.split(/\r?\n/); return {start:lines.shift()||'',headers:lines.join('\r\n'),body};
  }
  function isSqlInjection(text){
    const v=String(text||'').toLowerCase();
    const businessSqlConsole=/(?:userparam=|ccjdbc=|istransaction=|sqlexc=|name=)/i.test(v) && /(?:执行sql语句|临时视图|cleanup|_local|create\s+table|drop\s+table)/i.test(v);
    if(businessSqlConsole) return false;
    const hasAttackPrimitive=/(?:\bunion(?:\s+all)?\s+select\b|\bor\s+[\"']?\d+[\"']?\s*=\s*[\"']?\d+|\band\s+[\"']?\d+[\"']?\s*=\s*[\"']?\d+|--(?:\s|$)|\/\*|\b(?:sleep|benchmark|waitfor)\s*\(|\bdrop\s+(?:table|database)\b|\binformation_schema\b|\bload_file\s*\(|\binto\s+outfile\b)/i.test(v);
    if(!hasAttackPrimitive) return false;
    const dbAuditContext=/(?:\binstance_name\s*=|\bdb_name\s*=|\bschema_name\s*=|\btb_name\s*=|\bsql_content\s*=)/i.test(v);
    const isBusinessQuery=/\bsql_content\s*=\s*(?:select|with)\b/i.test(v) && /\binstance_name\s*=\s*[^&\s]+/i.test(v) && /\b(?:db_name|tb_name)\s*=/i.test(v);
    return !(dbAuditContext && isBusinessQuery);
  }
  function normalize(o){
    let request=parseRaw(get(o,aliases.request),true), response=parseRaw(get(o,aliases.response),false);
    const method=get(o,aliases.method)||request.start.split(' ')[0]||'GET'; const rawUrl=get(o,['url','full_url','fullurl','request_url','requesturl','uri','path','uri_path']); const uri=get(o,aliases.uri)||request.start.split(' ')[1]||'/'; const host=get(o,aliases.host)||((request.headers.match(/^host:\s*(.+)$/im)||[])[1]||'');
    let fullUrl=''; try { fullUrl=isAbsoluteUrl(rawUrl)?rawUrl:(host&&uri?`http://${host}${uri.startsWith('/')?'':'/'}${uri}`:''); } catch { fullUrl=''; }
    const embeddedPairText=`${get(o,['attacker_content','attackerContent','attacker'])} ${get(o,['victim_content','victimContent','victim'])}`;
    const status=get(o,aliases.status)||((response.start.match(/\s(\d{3})\b/)||[])[1]||'');
    const reqH=get(o,aliases.reqHeaders)||request.headers;
    const rawBody=get(o,aliases.reqBody)||request.body;
    const fallbackParams=get(o,['sql_content','sqlcontent','query','query_string','querystring','content','内容','攻击内容','attacker_content']);
    const reqB=rawBody||fallbackParams||((method === 'GET' && uri.includes('?')) ? uri.slice(uri.indexOf('?') + 1) : '');
    const pairIps=embeddedPairText.match(/(?:\d{1,3}\.){3}\d{1,3}/g)||[];
    const srcIp=get(o,aliases.srcIp)||pairIps[0]||'-';
    const dstIp=get(o,aliases.dstIp)||pairIps[1]||'-';
    const normalizedBody=reqB.replace(/%26/g,'&');
    const resH=get(o,aliases.resHeaders)||response.headers;
    const alertName=repairMojibake(get(o,aliases.alertName))||'-';
    const threatType=repairMojibake(get(o,aliases.threatType))||'-';
    const occurDays=get(o,['occur_days','occurdays','alert_days','告警出现天数','出现天数'])||'-';
    const isSqlAlert=/sql\s*(?:injection|注入)|sql注入/i.test(threatType);
    const sqli=isSqlAlert && isSqlInjection(`${method} ${uri}\n${reqH}\n${reqB}`);
    return { alertName, threatType, occurDays, attackResult:get(o,['attack_result','attackresult','攻击结果'])||'-', isSqlAlert, srcIp, srcPort:get(o,aliases.srcPort)||'-', dstIp, dstPort:get(o,aliases.dstPort)||'-', time:get(o,aliases.time)||'-', method, host, uri, fullUrl, status:status||'-', requestHeader:reqH, requestBody:normalizedBody, responseHeader:resH, sqli };
  }
  const e = s => String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  function evidenceHtml(value, r){
    const plain=String(value||''); const triage=threatTriage(r); if(!triage.real) return e(plain);
    const type=norm(r.threatType); let patterns=null;
    if(r.isSqlAlert) patterns=/(\bunion(?:\s+all)?\s+select\b|\bor\s+[\"']?\d+[\"']?\s*=\s*[\"']?\d+|\band\s+[\"']?\d+[\"']?\s*=\s*[\"']?\d+|--(?:\s|$)|\/\*|\b(?:sleep|benchmark|waitfor)\s*\(|\bdrop\s+(?:table|database)\b|\binformation_schema\b|\bload_file\s*\(|\binto\s+outfile\b)/ig;
    else if(/文件上传|webshell/i.test(type)) patterns=/(multipart\/form-data|filename=|\.php\b|\.jsp\b|\.aspx\b|\.war\b)/ig;
    else if(/命令执行|代码执行/i.test(type)) patterns=/(cmd\.exe|powershell|\/bin\/(?:sh|bash)|\bwhoami\b|\bcurl\b|\bwget\b|\beval\s*\()/ig;
    else if(/目录遍历/i.test(type)) patterns=/(\.\.\/|\.\.\\|%2e%2e(?:%2f|\/))/ig;
    else if(/跨站脚本|xss/i.test(type)) patterns=/(<script\b|javascript:|onerror\s*=|onload\s*=)/ig;
    else if(/漏洞利用|非授权访问|权限绕过/i.test(type)) patterns=/(\/admin\b|\/actuator\b|\/\.env\b|\/config\b|token=)/ig;
    if(!patterns) return e(plain); let out='',last=0,match; while((match=patterns.exec(plain))){ out+=e(plain.slice(last,match.index))+`<mark class="evidence">${e(match[0])}</mark>`; last=match.index+match[0].length; } return out?out+e(plain.slice(last)):e(plain);
  }
  function reqText(r){ return `${r.method} ${r.uri} HTTP/1.1${r.requestHeader?`\r\n${r.requestHeader}`:''}`; }
  function requestBodyLabel(r){ return r.requestBody ? (r.method === 'GET' && r.uri.includes('?') ? 'HTTP 请求参数（GET Query）' : 'HTTP 请求体') : 'HTTP 请求体'; }
  function displayedRequestBody(r){
    const decoded=$('decodeBase64').checked ? maybeDecodeBase64(r.requestBody) : '';
    return decoded ? `${decoded}\n\n[原始 Base64]\n${r.requestBody}` : r.requestBody;
  }
  function resText(r){ return r.status === '-' ? '-' : String(r.status); }
  function tag(r){ const n=Number(r.status); return `<span class="tag ${n>=500?'err':n>=400?'warn':'ok'}">${e(r.status)}</span>`; }
  function threatTriage(r){
    const type=norm(r.threatType); const payload=`${r.method} ${r.uri}\n${r.requestHeader}\n${r.requestBody}`.toLowerCase();
    const selected=selectedThreatTypes.has(type);
    if(r.isSqlAlert){
      const businessSqlConsole=/(?:userparam=|ccjdbc=|istransaction=|sqlexc=|name=)/i.test(payload) && /(?:执行sql语句|临时视图|cleanup|_local|create\s+table|drop\s+table)/i.test(payload);
      if(businessSqlConsole) return {enabled:true,real:false,result:'非真实攻击：识别为业务 SQL 控制台/临时视图维护操作'};
      return r.sqli ? {enabled:true,real:true,result:'真实攻击：命中 SQL 注入特征'} : {enabled:true,real:false,result:'非真实攻击：未命中当前 SQL 注入特征规则'};
    }
    const confirmed=/^(成功|已确认|true|yes|真实攻击)$/i.test(norm(r.attackResult));
    const blocked=/^(失败|阻断|已拦截|false|no|非真实攻击)$/i.test(norm(r.attackResult));
    if(blocked) return {enabled:true,real:false,result:'非真实攻击：告警结果显示请求已失败、阻断或拦截'};
    const patterns=[
      [/文件上传|webshell/i,/(?:multipart\/form-data|filename=|\.php\b|\.jsp\b|\.aspx\b|\.war\b)/,'文件上传行为特征'],
      [/命令执行|代码执行/i,/(?:cmd\.exe|powershell|\/bin\/(?:sh|bash)|\bwhoami\b|\bcurl\b|\bwget\b|\beval\s*\()/,'命令/代码执行特征'],
      [/目录遍历/i,/(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|\/))/,'目录遍历特征'],
      [/跨站脚本|xss/i,/(?:<script\b|javascript:|onerror\s*=|onload\s*=)/,'跨站脚本特征'],
      [/弱口令|暴力猜解/i,/(?:login|password|passwd|auth)/,'认证尝试特征'],
      [/漏洞利用|非授权访问|权限绕过/i,/(?:\/admin\b|\/actuator\b|\/\.env\b|\/config\b|token=)/,'漏洞利用/越权访问特征']
    ];
    const match=patterns.find(([typePattern])=>typePattern.test(type));
    if(match){ const real=confirmed||match[1].test(payload); return {enabled:true,real,result:real?`真实攻击：命中${match[2]}`:`非真实攻击：未命中${match[2]}`}; }
    return {enabled:true,real:confirmed,result:confirmed?'真实攻击：告警结果已确认成功':'待确认：当前类型缺少可用载荷特征或确认结果'};
  }
  function isRealAttack(r){ return threatTriage(r).real; }
  function alertTag(r, showTriage){ return r.isSqlAlert?`<span class="tag err">SQL 告警</span>${showTriage?` <span class="tag ${r.sqli?'err':'ok'}">${r.sqli?'真实攻击':'未命中'}</span>`:''}`:''; }
  function renderThreatFilters(){ const types=[...new Set(rows.map(r=>r.threatType).filter(t=>t&&t!=='-'))].sort(); $('threatFilters').innerHTML=types.length?`<div class="threat-filter-head"><span>按威胁类型筛选</span><span class="threat-filter-note">选择类型后可进一步限定真实攻击</span></div><div class="threat-grid">${types.map((type,i)=>{const id=`threat_${i}`; const realId=`real_threat_${i}`; const count=rows.filter(r=>r.threatType===type).length; const sql=/sql\s*(?:injection|注入)|sql注入/i.test(type); return `<div class="threat-card"><input id="${id}" class="threatTypeCheck" type="checkbox" data-type="${e(type)}" ${selectedThreatTypes.has(type)?'checked':''}/><label class="threat-name" for="${id}" title="${e(type)}">${e(type)}（${count}）${sql?' · SQL 研判':''}</label><label class="threat-real" for="${realId}"><input id="${realId}" class="realAttackTypeCheck" type="checkbox" data-type="${e(type)}" ${realAttackThreats.has(type)?'checked':''}/> 仅看真实攻击</label></div>`;}).join('')}</div>`:'<div class="empty">导入 CSV 后将按威胁类型生成筛选项。</div>'; document.querySelectorAll('.threatTypeCheck').forEach(el=>el.onchange=()=>{const type=el.dataset.type; el.checked?selectedThreatTypes.add(type):selectedThreatTypes.delete(type); if(!el.checked) realAttackThreats.delete(type); renderThreatFilters(); render();}); document.querySelectorAll('.realAttackTypeCheck').forEach(el=>el.onchange=()=>{const type=el.dataset.type; if(el.checked){realAttackThreats.add(type); selectedThreatTypes.add(type);}else realAttackThreats.delete(type); renderThreatFilters(); render();}); }
  function filteredIndexes(){ const q=$('filter').value.trim().toLowerCase(); const abnormalResponseOnly=$('abnormalResponseOnly').checked; const missingBodyOnly=$('missingBodyOnly').checked; const allRealAttackOnly=$('allRealAttackOnly').checked; const items=rows.map((r,i)=>({r,i})).filter(x=>{ const status=Number(x.r.status); const abnormal=status>=400&&status<=599; const typeSelected=selectedThreatTypes.size===0||selectedThreatTypes.has(x.r.threatType); const realOnly=realAttackThreats.has(x.r.threatType); const missingBody=!norm(x.r.requestBody); return typeSelected&&(!realOnly||isRealAttack(x.r))&&(!allRealAttackOnly||isRealAttack(x.r))&&(!abnormalResponseOnly||abnormal)&&(!missingBodyOnly||missingBody)&&(!q||Object.values(x.r).join(' ').toLowerCase().includes(q)); }); const mode=$('sortBy').value; const text=(v)=>String(v||'').localeCompare; items.sort((a,b)=>{ if(mode==='time_asc') return String(a.r.time).localeCompare(String(b.r.time)); if(mode==='time_desc') return String(b.r.time).localeCompare(String(a.r.time)); if(mode==='threat') return String(a.r.threatType).localeCompare(String(b.r.threatType),'zh-CN'); if(mode==='alert') return String(a.r.alertName).localeCompare(String(b.r.alertName),'zh-CN'); return 0; }); return items; }
  function render(){
    const indexes=filteredIndexes();
    $('records').innerHTML=indexes.length?indexes.map(({r,i})=>{ const triage=threatTriage(r); const triageTag=`<span class="tag ${triage.real?'err':'ok'}">${triage.real?'真实攻击':triage.result.includes('待确认')?'待确认':'非真实攻击'}</span>`; return `<div class="record ${active===i?'active':''}" data-i="${i}"><div class="line"><b>${e(r.method)} ${e(r.host||r.dstIp)}</b><span>${triageTag} ${tag(r)}</span></div><div class="line"><small><b>威胁类型：</b>${e(r.threatType)}</small><small>${e(r.uri)}</small></div><div class="line"><small><b>告警名称：</b>${e(r.alertName)}</small></div><div class="line"><small><b>源 IP：</b>${e(r.srcIp)}:${e(r.srcPort)} → ${e(r.dstIp)}:${e(r.dstPort)}</small></div></div>`; }).join(''):'<div class="empty">未找到匹配流量</div>';
    document.querySelectorAll('.record').forEach(el=>el.onclick=()=>{active=+el.dataset.i;render();});
    if(active>=0&&rows[active]) detail(rows[active]); else $('detail').innerHTML='<div class="empty">选择左侧记录后显示完整请求与响应内容。</div>';
  }
  function detail(r){ const result=threatTriage(r).result; const url=r.fullUrl||r.uri||'-'; const isReal=threatTriage(r).real; $('detail').innerHTML=`<div class="meta"><div><label>告警名称</label><code>${e(r.alertName)}</code></div><div><label>威胁类型</label><code>${e(r.threatType)}</code></div><div><label>研判结果</label><code>${e(result)}</code></div><div><label>告警出现天数</label><code>${e(r.occurDays||'-')}</code></div><div><label>请求 URL</label><code>${e(url)}</code></div><div><label>源 IP / 源端口</label><code>${e(r.srcIp)}:${e(r.srcPort)}</code></div><div><label>目的 IP / 目的端口</label><code>${e(r.dstIp)}:${e(r.dstPort)}</code></div><div><label>请求时间</label><code>${e(r.time)}</code></div></div><div class="sections">${isReal?'<div class="hint"><b style="color:#a71919">红色高亮为判定真实攻击的关键证据。</b></div>':''}<section class="block"><h3>HTTP 请求头</h3><pre>${evidenceHtml(reqText(r),r)}</pre></section><section class="block"><h3>${e(requestBodyLabel(r))}</h3><pre>${evidenceHtml(displayedRequestBody(r)||'(空)',r)}</pre></section><section class="block"><h3>HTTP 响应结果（状态码）</h3><pre>${e(resText(r))}</pre></section></div>`; }
  function summary(){ const abnormalCount=rows.filter(r=>{ const status=Number(r.status); return status>=400&&status<=599; }).length; $('count').textContent=rows.length; $('sqliCount').textContent=rows.filter(r=>r.isSqlAlert).length; $('errors').textContent=abnormalCount; $('sources').textContent=new Set(rows.map(r=>r.srcIp)).size; $('export').disabled=!rows.length; }
  function load(data){ rows=data.map(normalize); active=rows.length?0:-1; selectedThreatTypes.clear(); realAttackThreats.clear(); summary(); renderThreatFilters(); render(); }
  $('file').onchange=async ev=>{ const file=ev.target.files[0]; if(!file)return; try { const isExcel=/\.(xls|xlsx)$/i.test(file.name); if(isExcel){ if(!window.XLSX) throw new Error('Excel 解析组件未加载，请检查网络后重试'); const workbook=XLSX.read(await file.arrayBuffer(),{type:'array'}); const firstSheet=workbook.Sheets[workbook.SheetNames[0]]; if(!firstSheet) throw new Error('未找到可分析的工作表'); const csv=XLSX.utils.sheet_to_csv(firstSheet); load(parseCSV(csv)); } else { load(await readCsvFile(file)); } } catch(err){ alert('文件导入失败：'+err.message); } finally { ev.target.value=''; } };
  $('filter').oninput=render;
  $('sortBy').onchange=render;
  document.addEventListener('keydown', ev=>{ if(ev.key!=='ArrowUp'&&ev.key!=='ArrowDown') return; const target=ev.target; if(target && (target.tagName==='INPUT'||target.tagName==='TEXTAREA'||target.tagName==='SELECT'||target.isContentEditable)) return; const visible=filteredIndexes(); if(!visible.length) return; ev.preventDefault(); let position=visible.findIndex(item=>item.i===active); if(position<0) position=ev.key==='ArrowDown'?-1:0; position=ev.key==='ArrowDown'?Math.min(position+1,visible.length-1):Math.max(position-1,0); active=visible[position].i; render(); const selected=document.querySelector(`.record[data-i="${active}"]`); selected?.scrollIntoView({block:'nearest',behavior:'smooth'}); });
  $('decodeBase64').onchange=()=>{ if(active>=0&&rows[active]) detail(rows[active]); };
  $('abnormalResponseOnly').onchange=()=>{ $('abnormalMetric').classList.toggle('active',$('abnormalResponseOnly').checked); $('abnormalMetricHint').textContent=$('abnormalResponseOnly').checked?'已筛选异常响应':'点击筛选'; render(); };
  $('abnormalMetric').onclick=()=>{ $('abnormalResponseOnly').checked=!$('abnormalResponseOnly').checked; $('abnormalResponseOnly').dispatchEvent(new Event('change')); };
  $('missingBodyOnly').onchange=render;
  $('allRealAttackOnly').onchange=render;
  $('demo').onclick=()=>load(parseCSV(`timestamp,alert_name,ruleCategoryName,src_ip,src_port,dst_ip,dst_port,method,host,uri,request_headers,request_body,status,response_headers
2026-10-15 15:54:21,账号登录失败,暴力破解,10.10.8.23,49872,172.16.20.15,443,POST,api.example.internal,/v1/login,"Host: api.example.internal\nUser-Agent: curl/8.5\nContent-Type: application/json","{\"username\":\"admin\",\"password\":\"***\"}",401,"Content-Type: application/json\nServer: nginx"
2026-10-15 15:55:03,敏感文件下载,敏感文件下载,10.10.8.23,49893,172.16.20.15,80,GET,portal.example.internal,/admin/export,"Host: portal.example.internal\nAccept: */*",,200,"Content-Type: text/csv\nContent-Disposition: attachment; filename=users.csv"
2026-10-15 15:56:40,SQL 注入攻击,SQL注入,10.10.9.18,51102,192.168.1.8,8080,GET,192.168.1.8,/search?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--,"Host: 192.168.1.8:8080\nUser-Agent: sqlmap/1.8",,500,"Content-Type: text/plain"`));
  $('export').onclick=()=>{ const hs=['alert_name','src_ip','src_port','dst_ip','dst_port','method','host','uri','status','sql_alert','sqli_analysis','request_header','request_body','response_header']; const csv=[hs.join(','),...rows.map(r=>hs.map(k=>`"${String(r[{alert_name:'alertName',src_ip:'srcIp',src_port:'srcPort',dst_ip:'dstIp',dst_port:'dstPort',sql_alert:'isSqlAlert',sqli_analysis:'sqli',request_header:'requestHeader',request_body:'requestBody',response_header:'responseHeader'}[k]||k]||'').replace(/"/g,'""')}"`).join(','))].join('\r\n'); const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}));a.download='http_traffic_analysis.csv';a.click();URL.revokeObjectURL(a.href); };
})();
