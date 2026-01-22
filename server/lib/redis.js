const crypto=require('crypto');
let redis=null;
let memoryStore={bans:{},challenges:{},logs:[],suspends:{},cache:{}};
const REDIS_URL=process.env.REDIS_URL||process.env.UPSTASH_REDIS_URL||null;

async function initRedis(){
if(REDIS_URL){
try{
const{createClient}=require('redis');
// Upstash memerlukan TLS
const isUpstash=REDIS_URL.includes('upstash.io');
const url=REDIS_URL.startsWith('redis://')&&isUpstash?REDIS_URL.replace('redis://','rediss://'):REDIS_URL;
redis=createClient({
url:url,
socket:isUpstash?{tls:true,rejectUnauthorized:false}:undefined
});
redis.on('error',e=>console.error('Redis error:',e.message));
await redis.connect();
console.log('✅ Redis Connected'+(isUpstash?' (Upstash)':''));
return true;
}catch(e){console.error('❌ Redis Failed:',e.message);redis=null}}
console.log('⚠️ Using Memory Store - Data lost on restart!');
return false;
}
function isRedisConnected(){return redis&&redis.isOpen}
async function addBan(key,data){
const banId=data.banId||crypto.randomBytes(8).toString('hex').toUpperCase();
const banData={...data,banId,key,ts:new Date().toISOString()};
if(redis){await redis.hSet('shield:bans',banId,JSON.stringify(banData))}
else{memoryStore.bans[banId]=banData}
return banId;
}
async function getAllBans(){
if(redis){
const all=await redis.hGetAll('shield:bans');
return Object.values(all).map(v=>{try{return JSON.parse(v)}catch{return null}}).filter(Boolean);
}
return Object.values(memoryStore.bans);
}
async function removeBanById(banId){
if(!banId)return false;
const id=String(banId).toUpperCase();
if(redis){
const exists=await redis.hExists('shield:bans',id);
if(exists){await redis.hDel('shield:bans',id);return true}
const all=await redis.hGetAll('shield:bans');
for(const[k,v]of Object.entries(all)){
try{
const ban=JSON.parse(v);
if(ban.banId&&ban.banId.toUpperCase()===id){await redis.hDel('shield:bans',k);return true}
if(ban.hwid&&String(ban.hwid).toUpperCase()===id){await redis.hDel('shield:bans',k);return true}
if(ban.playerId&&String(ban.playerId)===banId){await redis.hDel('shield:bans',k);return true}
}catch{}}
return false;
}
if(memoryStore.bans[id]){delete memoryStore.bans[id];return true}
for(const[k,v]of Object.entries(memoryStore.bans)){
if(v.banId&&v.banId.toUpperCase()===id){delete memoryStore.bans[k];return true}
if(v.hwid&&String(v.hwid).toUpperCase()===id){delete memoryStore.bans[k];return true}
if(v.playerId&&String(v.playerId)===banId){delete memoryStore.bans[k];return true}
}
return false;
}
async function clearBans(){
if(redis){const len=await redis.hLen('shield:bans');if(len>0)await redis.del('shield:bans');return len}
const len=Object.keys(memoryStore.bans).length;memoryStore.bans={};return len;
}
async function isBanned(hwid,ip,userId){
const bans=await getAllBans();
for(const ban of bans){
if(hwid&&ban.hwid&&String(ban.hwid).toLowerCase()===String(hwid).toLowerCase())return{blocked:true,reason:ban.reason||'HWID Ban',banId:ban.banId};
if(userId&&ban.playerId&&String(ban.playerId)===String(userId))return{blocked:true,reason:ban.reason||'User Ban',banId:ban.banId};
if(ip&&ban.ip&&ban.ip===ip)return{blocked:true,reason:ban.reason||'IP Ban',banId:ban.banId};
}
return{blocked:false};
}
async function getBanCount(){
if(redis){try{return await redis.hLen('shield:bans')}catch{return 0}}
return Object.keys(memoryStore.bans).length;
}
async function setChallenge(id,data,ttl=120){
if(redis){await redis.setEx(`shield:challenge:${id}`,ttl,JSON.stringify(data))}
else{memoryStore.challenges[id]={...data,expiresAt:Date.now()+ttl*1000}}
}
async function getChallenge(id){
if(redis){const d=await redis.get(`shield:challenge:${id}`);return d?JSON.parse(d):null}
const c=memoryStore.challenges[id];
if(c&&c.expiresAt>Date.now())return c;
if(c)delete memoryStore.challenges[id];
return null;
}
async function deleteChallenge(id){
if(redis){await redis.del(`shield:challenge:${id}`)}
else{delete memoryStore.challenges[id]}
}
async function addLog(log){
if(redis){await redis.lPush('shield:logs',JSON.stringify(log));await redis.lTrim('shield:logs',0,499)}
else{memoryStore.logs.unshift(log);if(memoryStore.logs.length>500)memoryStore.logs.pop()}
}
async function getLogs(limit=50){
if(redis){const logs=await redis.lRange('shield:logs',0,limit-1);return logs.map(l=>{try{return JSON.parse(l)}catch{return null}}).filter(Boolean)}
return memoryStore.logs.slice(0,limit);
}
async function clearLogs(){
if(redis){await redis.del('shield:logs')}
else{memoryStore.logs=[]}
}
async function setCachedScript(script){
if(redis){if(script)await redis.setEx('shield:script',3600,script);else await redis.del('shield:script')}
else{if(script)memoryStore.cache.script={data:script,ts:Date.now()};else delete memoryStore.cache.script}
}
async function getCachedScript(){
if(redis){return await redis.get('shield:script')}
const c=memoryStore.cache.script;
if(c&&Date.now()-c.ts<3600000)return c.data;
return null;
}
async function addSuspend(type,value,data){
const key=`${type}:${value}`;
if(redis){await redis.hSet('shield:suspends',key,JSON.stringify(data))}
else{memoryStore.suspends[key]=data}
}
async function removeSuspend(type,value){
const key=`${type}:${value}`;
if(redis){await redis.hDel('shield:suspends',key)}
else{delete memoryStore.suspends[key]}
}
async function getAllSuspends(){
if(redis){
const all=await redis.hGetAll('shield:suspends');
return Object.entries(all).map(([k,v])=>{
try{const d=JSON.parse(v);const[type,value]=k.split(':');return{type,value,...d}}catch{return null}
}).filter(Boolean);
}
return Object.entries(memoryStore.suspends).map(([k,v])=>{const[type,value]=k.split(':');return{type,value,...v}});
}
async function getStats(){
return{
bans:await getBanCount(),
logs:redis?await redis.lLen('shield:logs'):memoryStore.logs.length,
suspends:redis?await redis.hLen('shield:suspends'):Object.keys(memoryStore.suspends).length,
redis:isRedisConnected()
};
}
initRedis();
module.exports={isRedisConnected,addBan,getAllBans,removeBanById,clearBans,isBanned,getBanCount,setChallenge,getChallenge,deleteChallenge,addLog,getLogs,clearLogs,addSuspend,removeSuspend,getAllSuspends,setCachedScript,getCachedScript,getStats};
