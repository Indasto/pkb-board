// Shared by Node and browsers. No keys or application data are bundled here.
export const VERSION=1, ITERATIONS=600000;
const utf8=new TextEncoder(),decode=new TextDecoder('utf-8',{fatal:true});
export const bytes=s=>utf8.encode(s);
export const text=b=>decode.decode(b);
export const random=(n=32)=>crypto.getRandomValues(new Uint8Array(n));
export function b64(b){let s='';for(let i=0;i<b.length;i+=16384)s+=String.fromCharCode(...b.subarray(i,i+16384));return btoa(s);}
export function unb64(s){if(typeof s!=='string'||s.length%4||!/^[A-Za-z0-9+/]*={0,2}$/.test(s))throw Error('Invalid encoding');return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
export const json=b=>JSON.parse(text(b));
export async function digest(b){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',b))].map(n=>n.toString(16).padStart(2,'0')).join('');}
export function kdfConfig(){return{salt:b64(random(16)),iterations:ITERATIONS};}
export function checkKdf(k){if(!k||!Number.isSafeInteger(k.iterations)||k.iterations<ITERATIONS||k.iterations>2000000||unb64(k.salt).length!==16)throw Error('Unsupported KDF');}
export async function master(pass,kdf){checkKdf(kdf);if(typeof pass!=='string'||!pass.length||pass.length>4096)throw Error('Invalid passphrase');const key=await crypto.subtle.importKey('raw',bytes(pass),'PBKDF2',false,['deriveBits']);return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:unb64(kdf.salt),iterations:kdf.iterations},key,256));}
export function aes(raw){if(raw.length!==32)throw Error('Invalid key');return crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);}
export async function deviceKey(base,secret,id,kdf){checkKdf(kdf);if(base.length!==32||secret.length!==32||!/^[a-f0-9-]{36}$/.test(id))throw Error('Invalid device');const ikm=new Uint8Array(64);ikm.set(base);ikm.set(secret,32);try{const key=await crypto.subtle.importKey('raw',ikm,'HKDF',false,['deriveKey']);return await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:unb64(kdf.salt),info:bytes('pkb-vault-device-v1:'+id)},key,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}finally{ikm.fill(0);}}
function aad(type,path,epoch){if(typeof epoch!=='string'||!epoch||typeof type!=='string'||typeof path!=='string')throw Error('Invalid context');return bytes(JSON.stringify({v:VERSION,type,path,epoch}));}
export async function seal(key,plain,type,path,epoch){const iv=random(12),data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(type,path,epoch),tagLength:128},key,plain);return{v:VERSION,epoch,iv:b64(iv),data:b64(new Uint8Array(data))};}
export async function open(key,envelope,type,path,epoch){if(envelope?.v!==VERSION||envelope.epoch!==epoch||unb64(envelope.iv).length!==12)throw Error('Invalid envelope');return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(envelope.iv),additionalData:aad(type,path,epoch),tagLength:128},key,unb64(envelope.data)));}
export async function wrap(base,device,dek,header){const key=await deviceKey(base,unb64(device.secret),device.id,header.kdf);return seal(key,dek,'wrap','keys.json#'+device.id,header.epoch);}
export async function unlock(pass,device,header){if(header?.v!==VERSION||!Array.isArray(header.devices))throw Error('Unsupported vault');const entry=header.devices.find(d=>d.id===device.id);if(!entry)throw Error('Device not registered or revoked');const base=await master(pass,header.kdf);try{const kek=await deviceKey(base,unb64(device.secret),device.id,header.kdf),raw=await open(kek,entry.wrap,'wrap','keys.json#'+device.id,header.epoch);try{return await aes(raw);}finally{raw.fill(0);}}finally{base.fill(0);}}
export function registration(code,repo){const data=json(unb64(code.trim()));if(data.v!==VERSION||data.repo!==repo||!/^[a-f0-9-]{36}$/.test(data.id)||unb64(data.secret).length!==32||unb64(data.claim).length!==32)throw Error('Invalid registration code');return data;}
// A device-specific MAC prevents a revoked device with an old shared DEK from
// impersonating an active device while delayed old-epoch inbox items are drained.
export async function authenticate(secret,path,envelope){const key=await crypto.subtle.importKey('raw',unb64(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);return {...envelope,mac:b64(new Uint8Array(await crypto.subtle.sign('HMAC',key,bytes(JSON.stringify({domain:'pkb-vault-inbox-v1',path,envelope})))))};}
export async function verify(secret,path,signed){const {mac,...envelope}=signed,key=await crypto.subtle.importKey('raw',unb64(secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);if(!await crypto.subtle.verify('HMAC',key,unb64(mac),bytes(JSON.stringify({domain:'pkb-vault-inbox-v1',path,envelope}))))throw Error('Invalid device authentication');return envelope;}
