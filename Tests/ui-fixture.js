// Offline QA only. This file is never copied into application resources.
window.__fixtureMessages=[];
window.webkit={messageHandlers:{nativeBridge:{postMessage(message){
 window.__fixtureMessages.push(message);
 const id=message.runId;
 if(message.action==='runFullCheck'){
 const cb=(name,data,delay=20)=>setTimeout(()=>window[name](data,id),delay+(window.__fixtureDelay||0));
 cb('onNativeSystemProxy',{summary:'离线验收样例 · 非实际网络'});
 cb('onNativeChinaIP',{success:true,ip:'8.8.8.8',countryCode:'US',locationText:'Fixture · 基础出口',source:'offline fixture'});
 cb('onNativeCloudflareIP',{success:true,ip:'8.8.8.8',countryCode:'US',locationText:'Fixture · Cloudflare',source:'offline fixture'});
 cb('onNativeClaudeRisk',{success:true,ip:'8.8.8.8',countryCode:'US',country:'United States',city:'Fixture city',isp:'Fixture Cloud',asn:'AS0000',timezone:'America/New_York',isHosting:true,exitSource:'offline fixture / Claude Trace',exitVerified:true,observedAt:'2026-10-28T06:00:00Z',signals:{hosting:{status:'detected',source:'offline fixture'},proxy:{status:'not_detected',source:'offline fixture'}}});
 cb('onNativeAvailability',[{domain:'claude.ai',status:'blocked',statusText:'访问受限',statusCode:403,latencyMs:120,reachable:true},{domain:'anthropic.com',status:'ok',statusText:'HTTP 响应正常',statusCode:200,latencyMs:122,reachable:true}]);
 cb('onNativeDNSLeak',{status:'error',statusText:'DNS 检测失败 / 结果未知',error:'离线超时样例',dnsIP:'未知',source:'offline fixture'},40);
 }else if(message.action==='checkUpdate'){setTimeout(()=>window.onNativeUpdateResult({latestVersion:'1.1.0',currentVersion:'1.1.1',releaseNotes:'离线版本比较样例'}),5);}
 else if(message.action==='exportReport'){window.__fixtureExport=JSON.parse(message.text);window.onNativeExportResult({success:true,error:''});}
}}}};
window.RTCPeerConnection=class {
 createDataChannel(){} createOffer(){return Promise.resolve({});}
 setLocalDescription(){queueMicrotask(()=>{for(const address of ['8.8.8.8','9.9.9.9'])this.onicecandidate?.({candidate:{address}});this.onicecandidate?.({candidate:null});});return Promise.resolve();}
 close(){}
};
