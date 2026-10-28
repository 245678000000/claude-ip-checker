const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Element {
 constructor(){this.children=[];this.text='';this.style={};this.dataset={};this.value='127.0.0.1:7890';this.classList={toggle(){},add(){},remove(){},contains(){return false;}};}
 set textContent(s){this.text=String(s);this.children=[];}get textContent(){return this.text+this.children.map(x=>x.textContent).join('');}
 replaceChildren(...children){this.text='';this.children=children;}appendChild(el){this.children.push(el);}append(...els){this.children.push(...els);}getContext(){return null;}
}
function setup(){
 const nodes={},store=new Map(),sent=[],timers=[];const doc={getElementById(id){return nodes[id]??=new Element();},createElement(){return new Element();},querySelectorAll(){return [];},body:new Element()};
 const c={document:doc,window:{webkit:{messageHandlers:{nativeBridge:{postMessage(x){sent.push(x)}}}},addEventListener(){}},navigator:{languages:['zh-CN'],userAgent:'Mac'},location:{protocol:'file:',hostname:''},Intl,Date,URL,Blob,AbortController,setTimeout(fn){timers.push(fn);return timers.length;},clearTimeout(){},setInterval(){},localStorage:{getItem:k=>store.get(k)??null,setItem:(k,v)=>store.set(k,v),removeItem:k=>store.delete(k)}};c.globalThis=c;vm.createContext(c);vm.runInContext(fs.readFileSync('Resources/diagnostics.js','utf8'),c);vm.runInContext(fs.readFileSync('Resources/app.js','utf8'),c);return {c,nodes,store,sent,timers,run:x=>vm.runInContext(x,c)};
}
const fixture={success:true,ip:'8.8.8.8',country:'US',countryCode:'US',isp:'Fixture',timezone:'America/New_York',exitVerified:true,exitSource:'fixture',signals:{proxy:{status:'not_detected',source:'fixture'}}};
test('stale callbacks do not overwrite current batch',()=>{const e=setup();e.run('triggerFullCheck();triggerFullCheck()');e.c.window.onNativeClaudeRisk(fixture,1);assert.notEqual(e.nodes.claudeIP.textContent,'8.8.8.8');e.c.window.onNativeClaudeRisk(fixture,2);assert.equal(e.nodes.claudeIP.textContent,'8.8.8.8');});
test('missing fields and failed DNS are gray, not successful',()=>{const e=setup();e.run('triggerFullCheck()');e.c.window.onNativeClaudeRisk(fixture,1);e.c.window.onNativeDNSLeak({status:'error',error:'timeout'},1);assert.equal(e.nodes.secVPN.textContent,'未取得情报');assert.equal(e.nodes.dnsStatusPill.className,'pill pill-gray');assert.equal(e.nodes.webrtcStatusPill.className,'pill pill-gray');});
test('mask includes history and changes no stored raw result',()=>{const e=setup();e.run('triggerFullCheck()');e.c.window.onNativeClaudeRisk(fixture,1);e.run('toggleHideIP(true)');assert.equal(e.nodes.claudeIP.textContent.includes('8.8.8.8'),false);assert.equal(e.nodes.historyContainer.textContent.includes('8.8.8.8'),false);assert.ok(e.store.get('claude_ip_history_v2').includes('8.8.8.8'));assert.equal(JSON.stringify(e.run('buildExport()')).includes('8.8.8.8'),false);});
test('cancelled export does not claim completion; late callback discarded',()=>{const e=setup();e.run('triggerFullCheck();cancelCheck()');e.c.window.onNativeClaudeRisk(fixture,1);assert.equal(e.run('buildExport().completed'),false);assert.equal(e.run('buildExport().runOutcome'),'cancelled');assert.notEqual(e.nodes.claudeIP.textContent,'8.8.8.8');});
test('HTTP error is distinct from transport reachable',()=>{const e=setup();e.run('triggerFullCheck()');e.c.window.onNativeAvailability([{domain:'claude.ai',reachable:true,status:'blocked',statusCode:403,statusText:'访问受限',latencyMs:42}],1);assert.equal(e.nodes.pingClaudePill.className,'pill pill-yellow');assert.equal(e.nodes.pingClaudeMs.textContent,'HTTP 403 · 42 ms');});
test('external fields are rendered as text, never markup',()=>{const e=setup();e.run('triggerFullCheck()');e.c.window.onNativeClaudeRisk({...fixture,isp:'<img src=x onerror=alert(1)>',signals:{proxy:{status:'detected',source:'<script>bad</script>'}}},1);assert.equal(e.nodes.attrISP.textContent,'<img src=x onerror=alert(1)>');assert.equal(e.nodes.banFactorList.children[0].textContent.includes('<script>'),true);});
test('cancel resolves pending labels without erasing completed observations',()=>{
 const e=setup();e.run('triggerFullCheck()');e.c.window.onNativeChinaIP({success:true,ip:'9.9.9.9'},1);e.run('cancelCheck()');
 assert.equal(e.nodes.cnIP.textContent,'9.9.9.9');assert.equal(e.nodes.claudeIP.textContent,'未完成（已取消）');assert.equal(e.nodes.secVPN.textContent,'未完成');
});
test('switching to unapplied custom mode keeps report provenance of the measured batch',()=>{
 const e=setup();e.run('triggerFullCheck()');e.c.window.onNativeClaudeRisk(fixture,1);e.run("setProxyMode('custom')");
 assert.equal(e.run('buildExport().mode'),'system');
});
test('hide IP covers source metadata and attribution factors',()=>{
 const e=setup();e.run('triggerFullCheck()');e.c.window.onNativeCloudflareIP({success:true,ip:'9.9.9.9',source:'https://1.1.1.1/cdn-cgi/trace'},1);
 e.c.window.onNativeClaudeRisk({...fixture,signals:{proxy:{status:'detected',source:'provider 8.8.8.8'}}},1);e.run('toggleHideIP(true)');
 assert.equal(e.nodes.cfSource.textContent.includes('1.1.1.1'),false);assert.equal(e.nodes.banFactorList.textContent.includes('8.8.8.8'),false);
});
test('WebRTC completion from an inactive batch never starts another batch',()=>{
 const e=setup();e.run('triggerFullCheck();cancelCheck();checkWebRTCLeak(1)');assert.equal(e.sent.filter(x=>x.action==='runFullCheck').length,1);
});
