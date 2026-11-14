// Normal public HTTPS + standard EIP-4361 SIWE and EIP-191 wallet signing. Never logs response bodies, keys or tokens.
import {randomUUID} from 'node:crypto';
import {mkdir,writeFile,appendFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
const env=process.env,dir=env.OUTSIDE_STATE_DIR||'outside-state',mode=process.argv[2]||'--check';
await mkdir(dir,{recursive:true});
const output=async(values)=>{if(env.GITHUB_OUTPUT)for(const [key,value]of Object.entries(values))await appendFile(env.GITHUB_OUTPUT,`${key}=${value}\n`);};
const origin=env.PROBE_ORIGIN||'https://aeonport.com';
const url=new URL(origin);
if(url.origin!==origin||url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','localhost'].includes(url.hostname)))throw Error('HTTPS_ORIGIN_REQUIRED');
const fail=code=>{throw Error(code);};
let account,brand;
async function request(path,data,headers={},expected=200){
 const response=await fetch(origin+path,{method:data===undefined?'GET':'POST',headers:{'content-type':'application/json','user-agent':'aeonport-outside-check/2.0',...(data===undefined?{}:{'idempotency-key':'outside-'+randomUUID()}),...headers},...(data===undefined?{}:{body:typeof data==='string'?data:JSON.stringify(data)}),redirect:'error',signal:AbortSignal.timeout(20000)});
 if(response.status!==expected)fail('HTTP_'+response.status);
 const text=await response.text();if(text.length>1024*1024)fail('RESPONSE_TOO_LARGE');try{return JSON.parse(text);}catch{fail('BAD_JSON');}
}
async function wallet(key=env.PROBE_WALLET_KEY){const {privateKeyToAccount}=await import('viem/accounts');account=privateKeyToAccount(key);}
let session;
async function login(){
 const c=await request('/api/auth/wallet/nonce'),issued=Date.parse(c.issued_at),expires=Date.parse(c.expiration_time),now=Date.now();
 if(c.domain!==url.host||c.uri!==origin||c.version!=='1'||!Number.isSafeInteger(c.chain_id)||c.chain_id<=0||!/^[-a-zA-Z0-9]{8,}$/.test(c.nonce)||c.statement!==brand+' Agent sign-in; no payment authorization.'||!Number.isFinite(issued)||!Number.isFinite(expires)||new Date(issued).toISOString()!==c.issued_at||new Date(expires).toISOString()!==c.expiration_time||issued>now+1000||expires<=now||expires-issued>300000||expires<=issued)fail('LOGIN_CHALLENGE');
 const {createSiweMessage}=await import('viem/siwe'),message=createSiweMessage({domain:c.domain,address:account.address,uri:c.uri,version:'1',chainId:c.chain_id,nonce:c.nonce,issuedAt:new Date(issued),expirationTime:new Date(expires),statement:c.statement});
 const result=await request('/api/auth/wallet/verify',{message,signature:await account.signMessage({message})});
 if(result.participant_kind!=='agent'||!result.agent_id||typeof result.token!=='string'||!result.token)fail('AGENT_IDENTITY');session=result.token;return result;
}
if(mode==='--enroll'){
try{
 // Store a new dedicated key directly in GitHub; normal SIWE verification also registers it.
 if(!env.PROBE_WALLET_KEY){const {generatePrivateKey}=await import('viem/accounts');const key=generatePrivateKey();const child=spawnSync('gh',['secret','set','PROBE_WALLET_KEY','--repo',env.GITHUB_REPOSITORY],{input:key,stdio:['pipe','ignore','ignore']});if(child.status!==0)fail('SECRET_STORE_FAILED');await wallet(key);}else await wallet();
 brand=(await request('/api/config')).brand.name;await login();console.log('Dedicated Agent enrolled through standard SIWE; key stored only in GitHub secret.');process.exit(0);
}catch{console.error('ENROLL_FAILED (details withheld)');process.exit(1);}
}
if(mode!=='--check')fail('UNKNOWN_MODE');
const started=new Date(env.PROBE_NOW||Date.now()).toISOString(),results={};
async function check(name,fn){try{await fn();results[name]={ok:true};}catch{results[name]={ok:false};}}
await check('config',async()=>{const config=await request('/api/config');if(typeof config.brand?.name!=='string')fail('CONFIG');brand=config.brand.name;
 // Homepage must be HTTP 200 (FAULT_RUNBOOK); failure uses the same "config" path: issue + run failure.
 const home=await fetch(origin+'/',{headers:{'user-agent':'aeonport-outside-check/2.0'},redirect:'error',signal:AbortSignal.timeout(20000)});if(home.status!==200)fail('HOMEPAGE_'+home.status);});
// 2026-11-13 owner ruling: a STALE or old-checked list is a warning only (screening continues on the last valid list).
await check('sanctions',async()=>{const h=await request('/api/sanctions/health');
 // Reject every status other than CURRENT/STALE first; reason text never downgrades a failure.
 if(h===null||typeof h!=='object'||(h.status!=='CURRENT'&&h.status!=='STALE'))fail('SANCTIONS');
 if(h.status==='STALE'){console.log('::warning::sanctions list STALE; reminder only');return;}
 const age=(Date.parse(started)-Date.parse(h.checked_at))/3600000;
 if(!Number.isFinite(age)||age<0||age>8)console.log('::warning::sanctions list last checked over 8 hours ago or time unreadable; reminder only');});
// Not enrolled yet (PROBE_WALLET_KEY absent): skip, do not report a failure. Becomes active after the 11-15 enroll run.
if(!env.PROBE_WALLET_KEY)console.log('agent_probe: SKIPPED (no PROBE_WALLET_KEY; not enrolled yet)');
else await check('agent_probe',async()=>{
 if(!brand)fail('CONFIG');await wallet();await login();
 const home=async(action,data)=>request('/api/home/actions',{action,data},{authorization:'Bearer '+session});
 const state=await home('home.memory.list',{}),value='outside-check:'+started+':'+randomUUID();
 const written=await home('home.memory.put',{expected_revision:state.revision,key:'outside-health-probe',value,cipher_label:'public health nonce; no private content'});
 const read=await home('home.memory.get',{key:'outside-health-probe'});
 if(read.value!==value||read.revision!==written.revision||read.revision!==state.revision+1)fail('READBACK');
});
if(env.PROBE_INFRA_FAILURE==='true')results.workflow={ok:false};
results.forced_failure={ok:env.PROBE_FORCE_FAILURE!=='true'};
const failed=Object.keys(results).filter(name=>!results[name].ok);
// The workflow owns all notification/throttle state, including when this script cannot run.
await writeFile(env.OUTSIDE_RESULT_FILE||'outside-result.json',JSON.stringify({started_at:started,results})+'\n');
await output({failed:String(failed.length>0),started_at:started});
console.log(Object.entries(results).map(([name,result])=>`${name}: ${result.ok?'PASS':'FAIL'}`).join('\n'));
