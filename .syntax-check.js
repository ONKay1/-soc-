
(() => {
  let rows = [], active = -1;
  const $ = id => document.getElementById(id);
  const aliases = { srcIp:['src_ip','source_ip','sourceip','sip','client_ip','clientip','remote_addr','remote_ip','源ip','源_ip'], srcPort:['src_port','source_port','sourceport','sport','client_port','源端口'], dstIp:['dst_ip','dest_ip','destination_ip','dstip','dip','server_ip','目的ip','目的_ip'], dstPort:['dst_port','dest_port','destination_port','dstport','dport','server_port','目的端口'], method:['method','http_method','请求方法'], host:['host','http_host','域名'], uri:['uri','url','path','request_uri','请求uri'], reqHeaders:['request_headers','req_headers','http_request_headers','请求头'], reqBody:['request_body','req_body','http_request_body','请求体'], status:['status','status_code','response_status','响应状态'], resHeaders:['response_headers','res_headers','http_response_headers','响应头'], request:['request','raw_request','http_request','原始请求'], response:['response','raw_response','http_response','原始响应'], time:['timestamp','time','datetime','时间'] };
  const norm = v => String(v ?? '').trim();
  const keyMap = o => { const m={}; Object.keys(o).forEach(k=>m[k.toLowerCase().replace(/[\s\-]/g,'_')]=o[k]); return m; };
  const get = (o, names) => { const m=keyMap(o); for(const n of names) if(m[n] !== undefined && norm(m[n])) return norm(m[n]); return ''; };
  const unquote = s => { s=norm(s); if(s.length>1 && s[0]=='"' && s.at(-1)=='"') return s.slice(1,-1).replace(/""/g,'"'); return s; };
  function parseCSV(text){
    const out=[]; let row=[], cell='', quoted=false;
    for(let i=0;i<text.length;i++){ const c=text[i], n=text[i+1]; if(c==='"'){ if(quoted&&n==='"'){cell+='"';i++;} else quoted=!quoted; } else if(c===','&&!quoted){row.push(cell);cell='';} else if((c==='\n'||c==='\r')&&!quoted){ if(c==='\r'&&n==='\n') i++; row.push(cell); if(row.some(x=>x.trim())) out.push(row); row=[];cell=''; } else cell+=c; }
    row.push(cell); if(row.some(x=>x.trim())) out.push(row); const headers=(out.shift()||[]).map(h=>h.trim()); return out.map(r=>Object.fromEntries(headers.map((h,i)=>[h,r[i]||''])));
  }
  function parseRaw(raw, isRequest){
    raw=unquote(raw).replace(/\\r\\n/g,'\r\n').replace(/\\n/g,'\n'); if(!raw) return {start:'',headers:'',body:''}; const split=raw.search(/\r?\n\r?\n/); const head=split<0?raw:raw.slice(0,split); const body=split<0?'':raw.slice(split).replace(/^\r?\n\r?\n/,''); const lines=head.split(/\r?\n/); return {start:lines.shift()||'',headers:lines.join('\r\n'),body};
  }
  function isSqlInjection(text){
    const v=String(text||'').toLowerCase();
    return /(?:\bunion(?:\s+all)?\s+select\b|\bselect\b[\s\S]{0,80}\bfrom\b|\binsert\s+into\b|\bupdate\b[\s\S]{0,80}\bset\b|\bdelete\s+from\b|\bdrop\s+(?:table|database)\b|\bor\s+[\"']?\d+[\"']?\s*=\s*[\"']?\d+|\band\s+[\"']?\d+[\"']?\s*=\s*[\"']?\d+|--(?:\s|$)|\/\*|\b(?:sleep|benchmark|waitfor)\s*\()/i.test(v);
  }
  function normalize(o){
    let request=parseRaw(get(o,aliases.request),true), response=parseRaw(get(o,aliases.response),false);
    const method=get(o,aliases.method)||request.start.split(' ')[0]||'GET'; const uri=get(o,aliases.uri)||request.start.split(' ')[1]||'/'; const host=get(o,aliases.host)||((request.headers.match(/^host:\s*(.+)$/im)||[])[1]||'');
    const status=get(o,aliases.status)||((response.start.match(/\s(\d{3})\b/)||[])[1]||'');
    const reqH=get(o,aliases.reqHeaders)||request.headers; const reqB=get(o,aliases.reqBody)||request.body; const resH=get(o,aliases.resHeaders)||response.headers;
    const sqli=isSqlInjection(`${method} ${uri}\n${reqH}\n${reqB}`);
    return { srcIp:get(o,aliases.srcIp)||'-', srcPort:get(o,aliases.srcPort)||'-', dstIp:get(o,aliases.dstIp)||'-', dstPort:get(o,aliases.dstPort)||'-', time:get(o,aliases.time)||'-', method, host, uri, status:status||'-', requestHeader:reqH, requestBody:reqB, responseHeader:resH, sqli };
  }
  const e = s => String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  function reqText(r){ return `${r.method} ${r.uri} HTTP/1.1${r.requestHeader?`\r\n${r.requestHeader}`:''}`; }
  function resText(r){ return `HTTP/1.1 ${r.status}${r.responseHeader?`\r\n${r.responseHeader}`:''}`; }
  function tag(r){ const n=Number(r.status); return `<span class="tag ${n>=500?'err':n>=400?'warn':'ok'}">${e(r.status)}</span>`; }
  function alertTag(r){ return r.sqli?'<span class="tag err">SQL 注入告警</span>':''; }
  function render(){
    const q=$('filter').value.trim().toLowerCase(); const onlySql=$('sqliOnly').checked; const indexes=rows.map((r,i)=>({r,i})).filter(x=>(!onlySql||x.r.sqli)&&(!q||Object.values(x.r).join(' ').toLowerCase().includes(q)));
    $('records').innerHTML=indexes.length?indexes.map(({r,i})=>`<div class="record ${active===i?'active':''}" data-i="${i}"><div class="line"><b>${e(r.method)} ${e(r.host||r.dstIp)}</b><span>${alertTag(r)} ${tag(r)}</span></div><div class="line"><small><b>源 IP：</b>${e(r.srcIp)}:${e(r.srcPort)} → ${e(r.dstIp)}:${e(r.dstPort)}</small><small>${e(r.uri)}</small></div></div>`).join(''):'<div class="empty">未找到匹配流量</div>';
    document.querySelectorAll('.record').forEach(el=>el.onclick=()=>{active=+el.dataset.i;render();});
    if(active>=0&&rows[active]) detail(rows[active]); else $('detail').innerHTML='<div class="empty">选择左侧记录后显示完整请求与响应内容。</div>';
  }
  function detail(r){ $('detail').innerHTML=`<div class="meta"><div><label>源 IP / 源端口</label><code>${e(r.srcIp)}:${e(r.srcPort)}</code></div><div><label>目的 IP / 目的端口</label><code>${e(r.dstIp)}:${e(r.dstPort)}</code></div><div><label>请求时间</label><code>${e(r.time)}</code></div><div><label>研判结果</label><code>${r.sqli?'SQL 注入告警':'未命中 SQL 注入特征'}　HTTP ${e(r.status)}</code></div></div><div class="sections"><section class="block"><h3>HTTP 请求头</h3><pre>${e(reqText(r))}</pre></section><section class="block"><h3>HTTP 请求体</h3><pre>${e(r.requestBody||'(空)')}</pre></section><section class="block"><h3>HTTP 响应头</h3><pre>${e(resText(r))}</pre></section></div>`; }
  function summary(){ $('count').textContent=rows.length; $('sqliCount').textContent=rows.filter(r=>r.sqli).length; $('errors').textContent=rows.filter(r=>Number(r.status)>=400).length; $('sources').textContent=new Set(rows.map(r=>r.srcIp)).size; $('export').disabled=!rows.length; }
  function load(data){ rows=data.map(normalize); active=rows.length?0:-1; summary(); render(); }
  $('file').onchange=async ev=>{ const f=ev.target.files[0]; if(!f)return; try { load(parseCSV(await f.text())); } catch(err){ alert('CSV 解析失败：'+err.message); } };
  $('filter').oninput=render;
  $('sqliOnly').onchange=render;
  $('demo').onclick=()=>load(parseCSV(`timestamp,src_ip,src_port,dst_ip,dst_port,method,host,uri,request_headers,request_body,status,response_headers
2026-10-15 15:54:21,10.10.8.23,49872,172.16.20.15,443,POST,api.example.internal,/v1/login,"Host: api.example.internal\nUser-Agent: curl/8.5\nContent-Type: application/json","{\"username\":\"admin\",\"password\":\"***\"}",401,"Content-Type: application/json\nServer: nginx"
2026-10-15 15:55:03,10.10.8.23,49893,172.16.20.15,80,GET,portal.example.internal,/admin/export,"Host: portal.example.internal\nAccept: */*",,200,"Content-Type: text/csv\nContent-Disposition: attachment; filename=users.csv"
2026-10-15 15:56:40,10.10.9.18,51102,192.168.1.8,8080,GET,192.168.1.8,/search?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--,"Host: 192.168.1.8:8080\nUser-Agent: sqlmap/1.8",,500,"Content-Type: text/plain"`));
  $('export').onclick=()=>{ const hs=['src_ip','src_port','dst_ip','dst_port','method','host','uri','status','sqli_alert','request_header','request_body','response_header']; const csv=[hs.join(','),...rows.map(r=>hs.map(k=>`"${String(r[{src_ip:'srcIp',src_port:'srcPort',dst_ip:'dstIp',dst_port:'dstPort',sqli_alert:'sqli',request_header:'requestHeader',request_body:'requestBody',response_header:'responseHeader'}[k]||k]||'').replace(/"/g,'""')}"`).join(','))].join('\r\n'); const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}));a.download='http_traffic_analysis.csv';a.click();URL.revokeObjectURL(a.href); };
})();
