const test = require('node:test');
const assert = require('node:assert/strict');
const D = require('../Resources/diagnostics.js');
test('mixed ICE addresses are reported even with a matching exit', () => {
 assert.equal(D.compareRTC(['8.8.8.8','9.9.9.9'],'8.8.8.8',{complete:true}).status,'mismatch');
});
test('no candidates and incomplete gathering stay unknown', () => {
 assert.equal(D.compareRTC([],'8.8.8.8',{complete:true}).status,'unknown');
 assert.equal(D.compareRTC(['8.8.8.8'],'8.8.8.8',{complete:false}).status,'unknown');
});
test('IPv6 equivalent spellings match, local and malformed addresses excluded', () => {
 assert.equal(D.compareRTC(['2606:4700:4700::1111'],'2606:4700:4700:0:0:0:0:1111',{complete:true}).status,'matched');
 for(const ip of ['100.127.0.1','169.254.2.1','198.19.0.1','999.1.1.1','fd00::1','192.168.1.1','x.local']) assert.equal(D.publicIP(ip),false,ip);
});
test('provider missing vs explicit negative is preserved', () => {
 assert.equal(D.signal({},'vpn').status,'unknown');
 assert.equal(D.signal({signals:{vpn:{status:'not_detected',source:'fixture'}}},'vpn').status,'not_detected');
});
test('old and undated history are excluded from recent changes', () => {
 const now=Date.parse('2026-10-28T06:00:00Z');
 assert.deepEqual(D.recentCountries([{countryCode:'US',timestamp:'2025-01-01T00:00:00Z',exitVerified:true},{countryCode:'JP',exitVerified:true}],now),[]);
});
test('Shanghai and Taipei have the same actual UTC offset', () => {
 const now=Date.parse('2026-10-28T06:00:00Z');
 assert.equal(D.offsetMinutes('Asia/Shanghai',now),480);
 assert.equal(D.offsetMinutes('Asia/Taipei',now),480);
 assert.equal(D.offsetMinutes('invalid/zone',now),null);
});
test('unknown data has no invented risk or confidence score', () => {
 assert.equal(D.assessRisk({success:true,ip:'8.8.8.8',signals:{}},{}).score,null);
});
test('risk is reference points, not probability; hosting preserves proxy', () => {
 const r=D.assessRisk({success:true,ip:'8.8.8.8',exitVerified:true,signals:{hosting:{status:'detected',source:'test'},proxy:{status:'detected',source:'test'}}},{});
 assert.equal(r.score,33); assert.equal(r.known,1); assert.equal(r.total,5);
});
test('redaction includes nested history, IPv6 and arbitrary IP-bearing strings', () => {
 const x=D.redact({ip:'8.8.8.8',history:[{ip:'2606:4700::1111'}],note:'resolver 9.9.9.9'});
 const s=JSON.stringify(x); for(const ip of ['8.8.8.8','2606:4700::1111','9.9.9.9'])assert.equal(s.includes(ip),false);
});
test('version ordering is numeric',()=>{ assert.equal(D.isNewer('1.10.0','1.9.0'),true); assert.equal(D.isNewer('1.1.0','1.1.1'),false); });
test('missing timezone is unknown rather than the current local timezone',()=>{
 for(const zone of [undefined,null,'','   '])assert.equal(D.offsetMinutes(zone),null);
});
test('report strings redact proxy credentials as well as IPs',()=>{
 const result=JSON.stringify(D.redact({note:'代理 http://alice:secret@proxy.example:7890',history:[{note:'socks5://bob:pwd@8.8.8.8:1080'}]}));
 for(const secret of ['alice','secret','bob','pwd','8.8.8.8'])assert.equal(result.includes(secret),false);
});
