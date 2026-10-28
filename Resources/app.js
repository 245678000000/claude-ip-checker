'use strict';
const APP_VERSION = '1.1.1';
const RELEASES = 'https://github.com/245678000000/claude-ip-checker/releases';
const $ = id => document.getElementById(id);
const text = (id,value) => {if($(id))$(id).textContent=String(value??'—');};
let currentProxyMode='system', measuredMode='system', currentRun=0, active=false, deadline=null, rtcCleanup=null;
let pending=new Set(), controllers=new Set(), sensitive=new Map(), runOutcome='idle';
let lastRiskData=null,lastDNS=null,lastRTC=null,lastAvailability=[],lastSystem=null,lastChina=null,lastCF=null;
let latestDownloadURL=RELEASES, shouldPopupUpdateModal=false;
const allSections=['system','china','cf','risk','dns','availability','rtc'];
function pref(key,fallback=''){try{return localStorage.getItem(key)??fallback;}catch{return fallback;}}
function savePref(key,value){try{localStorage.setItem(key,value);}catch{notice('本地存储未写入；本轮结果仍可查看');}}
let hideIP=pref('claude_ip_hide','false')==='true';
function notice(value){text('notice',value);}
function setPill(id,value,color='gray'){const el=$(id);if(el){el.textContent=value;el.className='pill pill-'+color;}}
function setSensitive(id,value){const clean=Diagnostics.maskCredentials(value??'—');sensitive.set(id,clean);text(id,hideIP?Diagnostics.maskText(clean):clean);}
function toggleHideIP(hide){hideIP=Boolean(hide);savePref('claude_ip_hide',String(hideIP));for(const [id,value] of sensitive)text(id,hideIP?Diagnostics.maskText(value):value);renderHistory();renderAssessment();}
function toggleTheme(){document.body.classList.toggle('dark');savePref('claude_ip_theme',document.body.classList.contains('dark')?'dark':'light');}
function accepts(run){return Number.isInteger(run)&&run===currentRun&&active;}
function finishSection(key,run){if(!accepts(run))return;pending.delete(key);text('runStatus',`检测进度 ${allSections.length-pending.size}/${allSections.length}`);if(!pending.size){active=false;runOutcome='complete';clearTimeout(deadline);$('btnRefreshAll').classList.remove('spinning');$('btnCancel').disabled=true;text('runStatus','本轮已结束 · '+new Date().toLocaleTimeString());}renderAssessment();}
function stopWork(){controllers.forEach(c=>c.abort());controllers.clear();if(rtcCleanup){rtcCleanup();rtcCleanup=null;}clearTimeout(deadline);}
function resolvePendingLabels(label,pill='未完成'){
 for(const id of ['cnIP','cfIP','claudeIP','cnLoc','cfLoc','claudeLoc','dnsExitInfo','webrtcIPInfo'])if($(id)?.textContent==='检测中…')setSensitive(id,label);
 for(const id of ['secVPN','secProxy','secTor','secCrawler','secAbuse','dnsStatusPill','webrtcStatusPill','pingClaudePill','pingAnthropicPill','attrTypePill'])if($(id)?.textContent==='检测中')setPill(id,pill);
}
function cancelCheck(){stopWork();const wasActive=active;currentRun++;active=false;runOutcome='cancelled';pending.clear();postToNative('cancelCheck');$('btnRefreshAll').classList.remove('spinning');$('btnCancel').disabled=true;if(wasActive){resolvePendingLabels('未完成（已取消）');renderAssessment();text('runStatus','检测已取消 · 已完成项目保留');notice('尚未完成的项目没有结论；后台原生请求将按超时结束。');}}
function setProxyMode(mode){currentProxyMode=mode;document.querySelectorAll('.proxy-tab').forEach(b=>b.classList.toggle('active',b.dataset.mode===mode));$('customProxyBox').classList.toggle('visible',mode==='custom');if(mode==='custom'){cancelCheck();notice('填写代理地址后点击“应用”；现有结果保留原检测模式，报告会标明。');}else triggerFullCheck();}
function getCustomProxyValue(){return $('customProxyInput').value.trim();}
function nativeAvailable(){return Boolean(window.webkit?.messageHandlers?.nativeBridge);}
function postToNative(action,payload={}){
 const body={action,proxyMode:currentProxyMode,customProxy:getCustomProxyValue(),runId:currentRun,...payload};
 if(nativeAvailable()){window.webkit.messageHandlers.nativeBridge.postMessage(body);return true;}
 if(/^https?:$/.test(location.protocol)&&['127.0.0.1','localhost'].includes(location.hostname)){runHTTPBridge(body);return true;}
 return false;
}
async function fetchJSON(path,query,run,callback,failure){
 const c=new AbortController();controllers.add(c);
 try{const r=await fetch(path+'?'+query,{signal:c.signal,cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);const data=await r.json();if(accepts(run))callback(data,run);}
 catch(e){if(e.name!=='AbortError'&&accepts(run))callback(failure,run);}finally{controllers.delete(c);}
}
function runHTTPBridge(body){
 const q=new URLSearchParams({proxyMode:body.proxyMode,customProxy:body.customProxy});const run=body.runId;
 if(body.action==='runFullCheck'){
  fetchJSON('/api/sys-proxy',q,run,window.onNativeSystemProxy,{summary:'系统代理状态未知'});
  fetchJSON('/api/china-ip',q,run,window.onNativeChinaIP,{success:false});
  fetchJSON('/api/cf-ip',q,run,window.onNativeCloudflareIP,{success:false});
  fetchJSON('/api/availability',q,run,window.onNativeAvailability,['claude.ai','anthropic.com'].map(domain=>({domain,status:'error',statusText:'请求失败'})));
  fetchJSON('/api/claude-risk',q,run,(d,id)=>{window.onNativeClaudeRisk(d,id);if(accepts(id)){q.set('cc',d.countryCode||'');fetchJSON('/api/dns-leak',q,id,window.onNativeDNSLeak,{status:'error',error:'DNS 请求失败'});}}, {success:false});
 }else if(body.action==='checkUpdate'){
  q.set('currentVersion',APP_VERSION);fetch('/api/check-update?'+q,{cache:'no-store'}).then(r=>{if(!r.ok)throw Error();return r.json();}).then(window.onNativeUpdateResult).catch(()=>window.onNativeUpdateResult({errorMsg:'更新检查失败',currentVersion:APP_VERSION}));
 }else if(body.action==='openExternalURL'){
  fetch('/api/open-url?'+new URLSearchParams({url:body.url}),{method:'POST'}).then(r=>{if(!r.ok)notice('打开链接失败');}).catch(()=>notice('打开链接失败'));
 }
}
function triggerFullCheck(){
 if(currentProxyMode==='custom'){
  try{const raw=getCustomProxyValue();const u=new URL(raw.includes('://')?raw:'http://'+raw);if(!raw||!u.hostname||!['http:','https:','socks5:','socks5h:'].includes(u.protocol))throw Error();}catch{notice('请输入有效的 HTTP / SOCKS5 代理地址。');return;}
 }
 stopWork();currentRun++;measuredMode=currentProxyMode;const run=currentRun;active=true;runOutcome='running';pending=new Set(allSections);lastRiskData=null;lastDNS=null;lastRTC=null;lastAvailability=[];lastChina=null;lastCF=null;lastSystem=null;sensitive.clear();
 $('btnRefreshAll').classList.add('spinning');$('btnCancel').disabled=false;notice('只测量网络与第三方情报，不读取 Claude 账户；所有导出默认脱敏。');text('runStatus','检测进度 0/7');
 for(const id of ['cnIP','cfIP','claudeIP','cnLoc','cfLoc','claudeLoc','dnsExitInfo','webrtcIPInfo'])setSensitive(id,'检测中…');
 for(const id of ['cnFlag','cfFlag','claudeFlag'])text(id,'—');
 for(const id of ['attrCountry','attrCity','attrASN','attrISP','attrTypeEn'])text(id,'—');
 for(const id of ['secVPN','secProxy','secTor','secCrawler','secAbuse','dnsStatusPill','webrtcStatusPill','pingClaudePill','pingAnthropicPill','attrTypePill'])setPill(id,'检测中');
 text('pingClaudeMs','');text('pingAnthropicMs','');setSensitive('cnSource','不使用显式代理；系统 TUN 路由仍可能生效');setSensitive('cfSource','探测 Cloudflare Trace');setSensitive('claudeSource','等待来源');
 $('ipv6Warning').classList.remove('visible');setSensitive('sysProxySummary','正在读取系统网络…');checkDeviceFingerprint();renderAssessment();
 deadline=setTimeout(()=>{
  if(!accepts(run))return;stopWork();active=false;runOutcome='timed_out';currentRun++;$('btnRefreshAll').classList.remove('spinning');$('btnCancel').disabled=true;text('runStatus','本轮超时 · 部分结果未知');
  resolvePendingLabels('结果未知（超时）','结果未知');postToNative('cancelCheck');
  renderAssessment();
 },65000);
 if(!postToNative('runFullCheck')){
  stopWork();active=false;runOutcome='unavailable';pending.clear();$('btnRefreshAll').classList.remove('spinning');$('btnCancel').disabled=true;text('runStatus','未连接桌面检测宿主');setSensitive('sysProxySummary','系统代理未检测');notice('请通过桌面应用启动检测；普通文件预览不生成模拟检测数据。');
  for(const id of ['cnIP','cfIP','claudeIP','cnLoc','cfLoc','claudeLoc','dnsExitInfo','webrtcIPInfo'])setSensitive(id,'未检测');
  for(const id of ['secVPN','secProxy','secTor','secCrawler','secAbuse','dnsStatusPill','webrtcStatusPill','pingClaudePill','pingAnthropicPill','attrTypePill'])setPill(id,'未检测');
 }
}
function refreshAvailability(){triggerFullCheck();}function refreshDNS(){triggerFullCheck();}
window.onNativeSystemProxy=(data,run)=>{if(!accepts(run))return;lastSystem=data;setSensitive('sysProxySummary',data.summary||'系统代理状态未知');finishSection('system',run);};
function renderExit(prefix,data){text(prefix+'Flag',/^[A-Z]{2}$/.test(data.countryCode||'')?data.countryCode:'—');setSensitive(prefix+'IP',data.success?data.ip:'获取失败');setSensitive(prefix+'Loc',data.locationText||'归属地未知');}
window.onNativeChinaIP=(data,run)=>{if(!accepts(run))return;lastChina=data;renderExit('cn',data);setSensitive('cnSource',`${data.source||'IPv4 探测'} · 不使用显式代理，仍可能受 TUN 影响`);finishSection('china',run);};
window.onNativeCloudflareIP=(data,run)=>{if(!accepts(run))return;lastCF=data;renderExit('cf',data);setSensitive('cfSource',data.source||'Cloudflare Trace');finishSection('cf',run);};
window.onNativeClaudeRisk=(data,run)=>{
 if(!accepts(run))return;lastRiskData=data;
 renderExit('claude',{...data,locationText:[data.country,data.city,data.isp].filter(Boolean).join(' · ')});
 setSensitive('claudeSource',data.success?`${data.exitVerified?'域名出口已观测':'通用出口回退'} · ${data.exitSource||'未知来源'}`:'出口证据未取得');
 $('ipv6Warning').classList.toggle('visible',Boolean(data.isIPv6));
 setSensitive('attrCountry',data.country);setSensitive('attrCity',data.city);setSensitive('attrASN',data.asn);setSensitive('attrISP',data.isp);
 const hosting=Diagnostics.signal(data,'hosting'),mobile=Diagnostics.signal(data,'mobile');
 setPill('attrTypePill',hosting.status==='detected'?'机房特征':mobile.status==='detected'?'移动网络':'类型待确认',hosting.status==='detected'?'yellow':'gray');setSensitive('attrTypeEn',hosting.status==='detected'?hosting.source:'未确认住宅或原生属性');
 const ids={vpn:'secVPN',proxy:'secProxy',tor:'secTor',crawler:'secCrawler',abuse:'secAbuse'};
 for(const [key,id] of Object.entries(ids)){const s=Diagnostics.signal(data,key);setPill(id,{detected:'来源标记命中',not_detected:'来源未标记',unknown:'未取得情报',error:'查询失败'}[s.status],s.status==='detected'?'yellow':s.status==='not_detected'?'green':'gray');$(id).title=Diagnostics.maskText(s.source);}
 if(data.success)saveHistoryItem(data);verifyTimezoneConsistency();finishSection('risk',run);checkWebRTCLeak(run);
};
window.onNativeAvailability=(list,run)=>{
 if(!accepts(run))return;lastAvailability=Array.isArray(list)?list:[];
 for(const [domain,prefix] of [['claude.ai','pingClaude'],['anthropic.com','pingAnthropic']]){const item=lastAvailability.find(x=>x.domain===domain);const status=item?.status||'error';setPill(prefix+'Pill',item?.statusText||'结果未知',status==='ok'?'green':['redirect','blocked','rate_limited'].includes(status)?'yellow':status==='error'?'gray':'red');text(prefix+'Ms',item?.statusCode?`HTTP ${item.statusCode} · ${item.latencyMs||0} ms`:'');}
 finishSection('availability',run);
};
window.onNativeDNSLeak=(data,run)=>{
 if(!accepts(run))return;lastDNS=data;setPill('dnsStatusPill',data.statusText||({error:'检测失败',unknown:'结果未知',observed:'已观测解析器',mismatch:'地理信息不一致'}[data.status]||'结果未知'),data.status==='mismatch'?'yellow':'gray');
 setSensitive('dnsExitInfo',data.dnsIP&&data.dnsIP!=='未知'?`${data.dnsIP} · ${data.dnsGeo||'位置未知'}`:'未取得解析器证据');setSensitive('dnsEvidence',data.error||`${data.source||'探测接口'} · 仅代表本次请求的解析路径，不证明系统全局 DNS 状态`);finishSection('dns',run);
};
function checkWebRTCLeak(run=currentRun){
 if(!accepts(run))return;if(rtcCleanup)rtcCleanup();
 const Peer=window.RTCPeerConnection||window.webkitRTCPeerConnection;const ips=[];let done=false,pc=null,timer=null;
 const finish=(complete,error=false)=>{if(done)return;done=true;clearTimeout(timer);try{pc?.close();}catch{}rtcCleanup=null;if(!accepts(run))return;lastRTC=Diagnostics.compareRTC(ips,lastRiskData?.ip,{complete,error});setPill('webrtcStatusPill',lastRTC.message,lastRTC.status==='mismatch'?'yellow':lastRTC.status==='matched'?'green':'gray');setSensitive('webrtcIPInfo',lastRTC.ips.join(', ')||'未取得公网候选');finishSection('rtc',run);};
 rtcCleanup=()=>{done=true;clearTimeout(timer);try{pc?.close();}catch{}};
 if(!Peer){finish(false);return;}
 try{
  pc=new Peer({iceServers:[{urls:'stun:stun.cloudflare.com:3478'},{urls:'stun:stun.l.google.com:19302'}]});
  pc.createDataChannel('diagnostics');pc.onicecandidate=e=>{if(e.candidate){const address=e.candidate.address||String(e.candidate.candidate).split(/\s+/)[4];if(address)ips.push(address);}else finish(true);};
  pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete')finish(true);};
  timer=setTimeout(()=>finish(false),5000);pc.createOffer().then(o=>{if(!done)return pc.setLocalDescription(o);}).catch(()=>finish(false,true));
 }catch{finish(false,true);}
}
function renderAssessment(){
 const r=Diagnostics.assessRisk(lastRiskData,{dns:lastDNS,rtc:lastRTC,history:loadHistory(),mode:measuredMode,localTimezone:Intl.DateTimeFormat().resolvedOptions().timeZone});
 text('banProbNum',r.score===null?'—':r.score+' 分');$('banProgressFill').style.width=(r.score||0)+'%';
 const color=r.score===null?'gray':r.score>=40?'red':r.score>=20?'yellow':'green';
 const paint={gray:'var(--text-secondary)',red:'#dc2626',yellow:'#d97706',green:'#16a34a'}[color];$('banProbNum').style.color=paint;$('banProgressFill').style.backgroundColor=paint;
 setPill('banProbLevel',r.score===null?'证据不足':r.score>=40?'较多提示':r.score>=20?'有待核对':'已知项较少提示',color);
 setPill('banSummaryBadge',active?'正在收集证据':r.incomplete?'数据不完整 · 保留未知项':'本轮证据已汇总',r.incomplete?'gray':color);
 text('banMainAdvice','0–100 为本工具启发式参考分，不是封号概率、官方信誉或账户可用性保证。');
 const box=$('banFactorList');box.replaceChildren();for(const f of r.factors){const div=document.createElement('div');div.className='ban-factor-item';div.textContent=hideIP?Diagnostics.maskText(f):Diagnostics.maskCredentials(f);box.appendChild(div);}
 text('trustScoreNum',r.known+'/5');setPill('trustLevelPill',r.known===5?'字段齐全':'情报不完整',r.known===5?'green':'gray');text('trustDescText','仅统计 VPN / Proxy / Tor / Crawler / Abuse 的明确返回值');$('gaugePointer').style.left=(r.known/5*100)+'%';
 setPill('claudeRegionPill','待官方核对');const a=lastAvailability.find(x=>x.domain==='claude.ai');setPill('sceneWebPill',a?.status==='ok'?'首页 HTTP 正常':a?.statusText||'未完成实测',a?.status==='ok'?'green':'gray');setPill('sceneCliPill','未执行功能验证');setPill('scenePayPill','未执行账户操作');
 const evidence={version:APP_VERSION,mode:measuredMode,observedAt:lastRiskData?.observedAt||null,exitSource:lastRiskData?.exitSource||null,exitVerified:lastRiskData?.exitVerified===true,signals:lastRiskData?.signals||{},dns:lastDNS,http:lastAvailability};
 text('evidenceJSON',JSON.stringify(Diagnostics.redact(evidence),null,2));
}
function loadHistory(){try{const x=JSON.parse(pref('claude_ip_history_v2',pref('claude_ip_history_v1','[]')));return Array.isArray(x)?x.filter(h=>h&&typeof h==='object').slice(0,100):[];}catch{return [];}}
function saveHistoryItem(data){const history=loadHistory();const item={ip:data.ip,country:data.country,countryCode:data.countryCode,isp:data.isp,timestamp:new Date().toISOString(),mode:currentProxyMode,exitSource:data.exitSource,exitVerified:data.exitVerified===true};if(history[0]?.ip===item.ip&&history[0]?.mode===item.mode)history[0]=item;else history.unshift(item);savePref('claude_ip_history_v2',JSON.stringify(history.slice(0,100)));renderHistory();}
function renderHistory(){
 const history=loadHistory(),box=$('historyContainer');text('historyCount',history.length);box.replaceChildren();
 if(!history.length){const p=document.createElement('div');p.className='history-empty';p.textContent='暂无历史记录';box.appendChild(p);return;}
 for(const item of history){const row=document.createElement('div');row.className='history-item';const left=document.createElement('div');const strong=document.createElement('strong');strong.textContent=hideIP?'[IP 已隐藏]':String(item.ip||'未知');left.appendChild(strong);const info=document.createElement('div');info.className='history-meta';const meta=[item.country||'地区未知',item.mode||'旧版模式未知',item.exitVerified?'域名出口':'通用/旧记录'].join(' · ');info.textContent=hideIP?Diagnostics.maskText(meta):Diagnostics.maskCredentials(meta);left.appendChild(info);const right=document.createElement('span');right.className='history-meta';const stamp=Date.parse(item.timestamp);right.textContent=Number.isFinite(stamp)?new Date(stamp).toLocaleString():'旧记录 · 日期未知';row.append(left,right);box.appendChild(row);}
}
function clearHistory(){try{localStorage.removeItem('claude_ip_history_v1');localStorage.removeItem('claude_ip_history_v2');}catch{}renderHistory();renderAssessment();}
function checkDeviceFingerprint(){text('devTimezone',Intl.DateTimeFormat().resolvedOptions().timeZone);text('devLang',(navigator.languages||[navigator.language]).join(', '));text('devOS',nativeAvailable()?'macOS · WKWebView':navigator.userAgent.includes('Windows')?'Windows · 浏览器宿主':'浏览器预览');text('devWebGL','未取得');text('devCanvas','未取得');try{const c=document.createElement('canvas'),gl=c.getContext('webgl');if(gl){const ext=gl.getExtension('WEBGL_debug_renderer_info');text('devWebGL',gl.getParameter(ext?ext.UNMASKED_RENDERER_WEBGL:gl.RENDERER));}}catch{}try{const c=document.createElement('canvas');c.width=200;c.height=30;const ctx=c.getContext('2d');ctx.font='14px Arial';ctx.fillText('Local diagnostics',8,18);let h=2166136261;for(const x of c.toDataURL()){h^=x.charCodeAt(0);h=Math.imul(h,16777619);}text('devCanvas',(h>>>0).toString(16));}catch{}verifyTimezoneConsistency();}
function verifyTimezoneConsistency(){const now=Date.now(),a=Diagnostics.offsetMinutes(Intl.DateTimeFormat().resolvedOptions().timeZone,now),b=Diagnostics.offsetMinutes(lastRiskData?.timezone,now);setPill('tzMatchPill',a!==null&&b!==null?`UTC 偏移差 ${Math.abs(a-b)} 分钟`:'出口时区未知',a!==null&&a===b?'green':'gray');}
function buildExport(){return Diagnostics.redact({version:APP_VERSION,exportedAt:new Date().toISOString(),redacted:true,mode:measuredMode,completed:runOutcome==='complete',runOutcome,risk:lastRiskData,dns:lastDNS,rtc:lastRTC,http:lastAvailability,history:loadHistory(),note:'启发式网络诊断；未知不代表安全；无账户验证'});}
function exportReport(){const content=JSON.stringify(buildExport(),null,2);if(nativeAvailable()){postToNative('exportReport',{text:content});return;}const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([content],{type:'application/json'}));a.download='claude-ip-diagnostics-redacted.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),5000);notice('已生成脱敏报告。');}
window.onNativeExportResult=res=>notice(res.success?'脱敏报告已保存':res.error||'导出已取消');
function openExternal(raw){try{const u=new URL(raw);if(u.protocol!=='https:'||u.username||u.password)throw Error();if(!postToNative('openExternalURL',{url:u.href}))window.open(u.href,'_blank','noopener,noreferrer');}catch{notice('仅打开有效 HTTPS 链接。');}}
function triggerUpdateCheck(show){shouldPopupUpdateModal=Boolean(show);if(show){$('updateModal').classList.add('visible');text('updateModalTitle','检查版本更新');text('updateModalBody','正在连接 GitHub Releases…');$('btnDownloadUpdate').style.display='none';}if(!postToNative('checkUpdate',{currentVersion:APP_VERSION}))window.onNativeUpdateResult({errorMsg:'请在桌面宿主中检查更新',currentVersion:APP_VERSION});}
window.onNativeUpdateResult=res=>{if(!res)return;const hasUpdate=!res.errorMsg&&Diagnostics.isNewer(res.latestVersion,APP_VERSION);$('updateRedDot').classList.toggle('visible',hasUpdate);latestDownloadURL=res.downloadURL||res.releaseURL||RELEASES;if(!shouldPopupUpdateModal&&!hasUpdate)return;text('updateModalTitle',res.errorMsg?'更新检查失败':hasUpdate?'发现新版 '+res.latestVersion:'未发现更高版本');text('updateModalBody',res.errorMsg||`当前 v${APP_VERSION} · 远程 ${res.latestVersion}\n${res.releaseNotes||''}`);$('btnDownloadUpdate').style.display=hasUpdate?'inline-block':'none';};
function closeUpdateModal(){$('updateModal').classList.remove('visible');}function downloadLatestRelease(){openExternal(latestDownloadURL);}
window.addEventListener('DOMContentLoaded',()=>{
 document.body.classList.toggle('dark',pref('claude_ip_theme')==='dark');$('hideIpCheckbox').checked=hideIP;renderHistory();
 if(/^https?:$/.test(location.protocol)&&['127.0.0.1','localhost'].includes(location.hostname)){
  setInterval(()=>fetch('/api/heartbeat',{method:'POST',keepalive:true}).catch(()=>{}),2500);
  // Heartbeat expiry handles window closure; reload must keep the host alive.
 }
 triggerFullCheck();
});
