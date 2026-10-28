/* Shared deterministic rules. Reference points are not account-ban probabilities. */
(function(root,factory){const api=factory();if(typeof module==='object')module.exports=api;else root.Diagnostics=api;})(globalThis,()=>{
'use strict';
const securityKeys=['vpn','proxy','tor','crawler','abuse'];
function ipv4(ip){if(typeof ip!=='string'||!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip))return null;const n=ip.split('.').map(Number);return n.every((x,i)=>x<=255&&String(x)===ip.split('.')[i])?n:null;}
function normalizeIP(input){
 if(typeof input!=='string')return null;let ip=input.trim().toLowerCase();const v4=ipv4(ip);if(v4)return v4.join('.');
 if(!ip.includes(':')||ip.includes('%')||/[^a-f0-9:.]/.test(ip))return null;
 if(ip.includes('.')){const at=ip.lastIndexOf(':');const n=ipv4(ip.slice(at+1));if(!n)return null;ip=ip.slice(0,at+1)+((n[0]<<8)|n[1]).toString(16)+':'+((n[2]<<8)|n[3]).toString(16);}
 const sides=ip.split('::');if(sides.length>2)return null;
 const a=sides[0]?sides[0].split(':'):[],b=sides.length===2&&sides[1]?sides[1].split(':'):[];
 if([...a,...b].some(x=>!/^[a-f0-9]{1,4}$/.test(x)))return null;
 if(sides.length===1&&a.length!==8||sides.length===2&&a.length+b.length>=8)return null;
 const words=sides.length===2?[...a,...Array(8-a.length-b.length).fill('0'),...b]:a;
 const ns=words.map(x=>parseInt(x,16));
 if(ns.slice(0,5).every(x=>x===0)&&ns[5]===65535)return [ns[6]>>8,ns[6]&255,ns[7]>>8,ns[7]&255].join('.');
 return ns.map(x=>x.toString(16).padStart(4,'0')).join(':');
}
function publicIP(value){
 const ip=normalizeIP(value);if(!ip)return false;const n=ipv4(ip);
 if(n){const [a,b,c]=n;return !(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&b===168||a===100&&b>=64&&b<=127||a===198&&(b===18||b===19)||a===192&&b===0||a===198&&b===51&&c===100||a===203&&b===0&&c===113);}
 const w=ip.split(':').map(x=>parseInt(x,16));return w[0]>=0x2000&&w[0]<=0x3fff&&!(w[0]===0x2001&&w[1]===0xdb8);
}
function compareRTC(addresses,exit,{complete=false,error=false}={}){
 const ips=[...new Set(addresses.filter(publicIP).map(normalizeIP))],ref=normalizeIP(exit);
 if(error)return {status:'error',ips,message:'WebRTC 探测失败'};
 if(!ref||!ips.length)return {status:'unknown',ips,message:!ref?'出口未确定，暂不比较':'未取得公网候选，结果未知'};
 if(ips.some(ip=>ip!==ref))return {status:'mismatch',ips,message:'发现与所测出口不同的 UDP 地址'};
 return {status:complete?'matched':'unknown',ips,message:complete?'已观测候选与所测出口一致':'收集超时，结果不完整'};
}
function signal(data,key){const s=data?.signals?.[key];return s&&['detected','not_detected','unknown','error'].includes(s.status)?s:{status:'unknown',source:'未取得有效情报'};}
function recentCountries(history,now=Date.now(),mode){return [...new Set((Array.isArray(history)?history:[]).filter(h=>{const t=Date.parse(h.timestamp);return h.exitVerified===true&&Number.isFinite(t)&&t<=now&&now-t<=86400000&&(!mode||h.mode===mode);}).map(h=>h.countryCode).filter(x=>typeof x==='string'&&/^[A-Z]{2}$/.test(x)))];}
function offsetMinutes(zone,now=Date.now()){
 if(typeof zone!=='string'||!zone.trim())return null;
 try{const f=new Intl.DateTimeFormat('en-GB',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'});const p=Object.fromEntries(f.formatToParts(new Date(now)).filter(x=>x.type!=='literal').map(x=>[x.type,Number(x.value)]));return Math.round((Date.UTC(p.year,p.month-1,p.day,p.hour,p.minute,p.second)-Math.floor(now/1000)*1000)/60000);}catch{return null;}
}
function assessRisk(data,context={}){
 const known=securityKeys.filter(k=>['detected','not_detected'].includes(signal(data,k).status)).length;
 if(!data?.success||!normalizeIP(data.ip))return {score:null,known,total:5,factors:['未取得有效出口 IP'],incomplete:true};
 let score=0,observed=known;const factors=[];
 const weights={hosting:11,vpn:12,proxy:22,tor:35,crawler:10,abuse:40};
 for(const [key,weight] of Object.entries(weights)){const s=signal(data,key);if(s.status==='detected'){score+=weight;observed++;factors.push(`${key}: 来源标记命中，参考权重 +${weight}（${s.source}）`);}}
 if(data.exitVerified!==true)factors.push(`通用出口回退：${data.exitSource||'来源未知'}；未确认 Claude 域名出口`);
 if(context.dns?.status==='mismatch'){score+=10;observed++;factors.push('DNS 地理信息与出口不同 +10；这不单独证明泄露');}
 if(context.rtc?.status==='mismatch'){score+=20;observed++;factors.push('WebRTC 候选与所测出口不一致 +20；请核对分流规则');}
 const countries=recentCountries(context.history,context.now,context.mode);
 if(countries.length>=3){score+=5;factors.push(`最近 24 小时同模式观测到 ${countries.length} 个地区 +5`);}
 const here=offsetMinutes(context.localTimezone,context.now),there=offsetMinutes(data.timezone,context.now);
 if(here!==null&&there!==null)factors.push(`当前时刻 UTC 偏移差：${Math.abs(here-there)} 分钟（仅信息项）`);
 if(known<5)factors.push(`安全情报覆盖 ${known}/5；缺失字段不代表未命中`);
 if(!['observed','mismatch'].includes(context.dns?.status))factors.push('DNS 测量证据未完整取得');
 if(!['matched','mismatch'].includes(context.rtc?.status))factors.push('WebRTC 测量证据未完整取得');
 if(!factors.length)factors.push('当前已知项未命中规则');
 return {score:observed?Math.min(100,score):null,known,total:5,factors,incomplete:known<5||data.exitVerified!==true||!['observed','mismatch'].includes(context.dns?.status)||!['matched','mismatch'].includes(context.rtc?.status)};
}
function maskCredentials(text){return String(text??'').replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/gi,'$1[凭据已隐藏]@');}
function maskText(text){return maskCredentials(text).replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,'[IP 已隐藏]').replace(/(?<![\w])(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9:.]*/g,m=>normalizeIP(m)?'[IP 已隐藏]':m);}
function redact(value,key=''){
 if(typeof value==='string'){if(/^(ip|dnsIP|customProxy|httpProxy|socksProxy|devCanvas|canvas|fingerprint)$/i.test(key))return '[已脱敏]';return maskText(value);}
 if(Array.isArray(value))return value.map(x=>redact(x));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,redact(v,k)]));
 return value;
}
function isNewer(a,b){const parse=v=>String(v).replace(/^v/,'').split('.').map(x=>parseInt(x,10)||0);const x=parse(a),y=parse(b);for(let i=0;i<Math.max(x.length,y.length);i++){if((x[i]||0)!==(y[i]||0))return (x[i]||0)>(y[i]||0);}return false;}
return {securityKeys,normalizeIP,publicIP,compareRTC,signal,recentCountries,offsetMinutes,assessRisk,maskCredentials,maskText,redact,isNewer};
});
