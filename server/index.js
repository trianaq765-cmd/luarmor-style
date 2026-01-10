const express=require('express'),axios=require('axios'),crypto=require('crypto'),cors=require('cors'),helmet=require('helmet'),rateLimit=require('express-rate-limit'),path=require('path'),fs=require('fs'),config=require('./config'),db=require('./lib/redis'),webhook=require('./lib/webhook');
const app=express(),SESSIONS=new Map(),dWL={u:new Set(),h:new Set(),i:new Set()},susp={h:new Map(),u:new Map(),s:new Map()};
const BOTS=['python','curl','wget','axios','node','got','undici','java','http','ruby','perl','php','postman','insomnia','bot','crawl','spider','slurp','google','bing','yandex','twitter','discord','telegram','burp','fiddler','charles','nmap','nikto','sqlmap','scanner','monitor'];
const HEADERS_E=['x-hwid','x-roblox-id','x-job-id'];
const ALLOWED_E=['synapse','script-ware','delta','fluxus','krnl','oxygen','evon','hydrogen','vegax','trigon','solara','wave','codex','celery','swift','electron','sentinel','valyse','nihon','jjsploit','arceus','roblox','wininet'];
const u={
hmac:(d,k)=>crypto.createHmac('sha256',k).update(d).digest('hex'),
safeCmp:(a,b)=>{if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;try{return crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b))}catch{return false}},
ip:r=>(r.headers['x-forwarded-for']||'').split(',')[0].trim()||r.ip||'0.0.0.0',
hwid:r=>r.headers['x-hwid']||r.body?.hwid||null,
sessKey:(u,h,t,s)=>u.hmac(`${u}:${h}:${t}`,s).substring(0,32)
};
function getClient(r){const ua=(r.headers['user-agent']||'').toLowerCase(),h=r.headers,eS=HEADERS_E.filter(x=>h[x]).length;if(BOTS.some(p=>ua.includes(p))&&eS===0)return'bot';if(r.headers['sec-fetch-mode'])return'browser';if(!ua||ua.length<5)return'bot';if(eS>=2||ALLOWED_E.some(e=>ua.includes(e)))return'executor';return'unknown'}
async function checkWL(h,u,r){const ip=u.ip(r);if(config.WHITELIST_IPS?.includes(ip)||dWL.i.has(ip))return true;if(u){const id=parseInt(u);if(config.WHITELIST_USER_IDS?.includes(id)||dWL.u.has(id))return true}if(h&&(config.WHITELIST_HWIDS?.includes(String(h))||dWL.h.has(String(h))))return true;return false}
function isBlocked(r){if(r.path==='/health')return false;const ip=u.ip(r);if(config.WHITELIST_IPS?.includes(ip)||dWL.i.has(ip))return false;return['bot','browser','unknown'].includes(getClient(r))}
function genFake(){const rS=l=>{const c='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';let s='';for(let i=0;i<l;i++)s+=c[Math.floor(Math.random()*c.length)];return s};const v=Array(15).fill(0).map(()=>rS(6));return`--[[ Protected v2 ]]\nlocal ${v[0]}={ "${rS(32)}", "${rS(32)}", "${rS(32)}" };\nlocal ${v[1]}=function(${v[2]}) return string.byte(${v[2]})*${Math.floor(Math.random()*99)} end;\nfor ${v[3]}=1,#${v[0]} do ${v[1]}(${v[0]}[${v[3]}]) end;\nerror("Auth Failed: Invalid HWID or IP",0);`}
function encLoader(s,k){const kb=Buffer.from(k),sb=Buffer.from(s),e=[];for(let i=0;i<sb.length;i++)e.push(sb[i]^kb[i%kb.length]);return Buffer.from(e).toString('base64')}
function genLKey(r){return crypto.createHash('md5').update([r.headers['x-hwid']||'',r.headers['x-roblox-id']||'',config.LOADER_KEY].join(':')).digest('hex').substring(0,16)}
function chunk(s,z){const c=[];for(let i=0;i<s.length;i+=z)c.push(s.substring(i,i+z));return c}
function encChunk(c,k){const e=[];for(let i=0;i<c.length;i++)e.push((c.charCodeAt(i)^k.charCodeAt(i%k.length))&255);return e}
async function prepChunks(s,ch){const n=config.CHUNK_COUNT||3,z=Math.ceil(s.length/n),c=chunk(s,z),base=crypto.createHash('sha256').update((ch.hwid||'')+(ch.userId||'')+config.SECRET_KEY).digest('hex'),k=c.map((_,i)=>crypto.createHash('md5').update(base+i).digest('hex'));return{chunks:c.map((x,i)=>({index:i,data:encChunk(x,k[i])})),keys:k,total:c.length}}
async function log(r,a,s,d={}){const l={ip:u.ip(r),hwid:u.hwid(r),userId:r.headers['x-roblox-id']||r.body?.userId,ua:(r.headers['user-agent']||'').substring(0,100),action:a,success:s,client:getClient(r),ts:new Date().toISOString(),...d};await db.addLog(l);return l}
function getSuspended(h,u,s){const now=Date.now();const chk=(m,k)=>{if(m.has(k)){const v=m.get(k);if(!v.expiresAt||new Date(v.expiresAt).getTime()>now)return v;m.delete(k)}return null};return chk(susp.s,s)||chk(susp.h,h)||chk(susp.u,String(u))}
async function loadSusp(){const a=await db.getAllSuspends();if(a)a.forEach(x=>{if(x.type==='hwid')susp.h.set(x.value,x);if(x.type==='userId')susp.u.set(x.value,x);if(x.type==='session')susp.s.set(x.value,x)})}
async function getSrc(){const c=await db.getCachedScript();if(c)return c;if(!config.SCRIPT_SOURCE_URL)return null;try{const r=await axios.get(config.SCRIPT_SOURCE_URL);if(r.data){await db.setCachedScript(r.data);return r.data}}catch(e){}return null}
function wrap(s,url){const o=(config.OWNER_USER_IDS||[]).join(','),w=(config.WHITELIST_USER_IDS||[]).join(','),sid=crypto.randomBytes(16).toString('hex'),spy=config.ANTI_SPY_ENABLED!==false,ab=config.AUTO_BAN_SPYTOOLS===true;
return`--[[ Shield V4 ]]\nlocal _C={o={${o}},w={${w}},bu="${url}/api/ban",wu="${url}/api/webhook/suspicious",hu="${url}/api/heartbeat",sid="${sid}",as=${spy},ab=${ab},int=45}\nlocal P=game:GetService("Players")local L=P.LocalPlayer local G=game:GetService("CoreGui") local H=game:GetService("HttpService") local A=true local S={} local BL={"spy","dex","remote","http","dumper","console"}\nlocal function hp(u,d)if request then pcall(function()request({Url=u,Method="POST",Headers={["Content-Type"]="application/json",["x-session-id"]=_C.sid},Body=H:JSONEncode(d)})end)end end\nlocal function cl(m)if not A then return end;A=false;pcall(function()game:GetService("StarterGui"):SetCore("SendNotification",{Title="Security",Text=m,Duration=5})end);task.wait(1);L:Kick(m)end\ntask.spawn(function()pcall(function()for _,g in pairs(G:GetChildren())do S[g]=true end end);task.wait(1);while A do pcall(function()for _,g in pairs(G:GetChildren())do if not S[g]then local n=g.Name:lower();for _,b in ipairs(BL)do if n:find(b)and not n:find("roblox")then hp(_C.wu,{userId=L.UserId,tool=g.Name});if _C.ab then hp(_C.bu,{hwid="UNK",playerId=L.UserId,reason="Spy: "..g.Name,sessionId=_C.sid})end;cl("Spy Detected")end end end end end);task.wait(3)end end)\ntask.spawn(function()while A do local r;if request then local ok,res=pcall(function()return request({Url=_C.hu,Method="POST",Headers={["Content-Type"]="application/json"},Body=H:JSONEncode({sessionId=_C.sid,userId=L.UserId})})end);if ok and res.StatusCode==200 then r=H:JSONDecode(res.Body)end end;if r and r.action=="TERMINATE"then cl(r.reason)end;task.wait(_C.int)end end)\n${s}`}
function ldr(u){return`local S="${u}" local H=game:GetService("HttpService") local P=game:GetService("Players") local L=P.LocalPlayer local function n(m)pcall(function()game:GetService("StarterGui"):SetCore("SendNotification",{Title="Loader",Text=m,Duration=3})end)end local function hp(e,d)local r=(syn and syn.request)or request or http_request;if not r then return nil end;local s,v=pcall(function()return r({Url=S..e,Method="POST",Headers={["Content-Type"]="application/json",["x-hwid"]=(gethwid and gethwid()or"UNK"),["x-roblox-id"]=tostring(L.UserId)},Body=H:JSONEncode(d)})end);if s and v.StatusCode==200 then return H:JSONDecode(v.Body)end;return nil end local function xd(d,k)local r={};for i=1,#d do table.insert(r,string.char(bit32.bxor(d[i],string.byte(k,((i-1)%#k)+1))))end;return table.concat(r)end n("Connecting...") local c=hp("/api/auth/challenge",{userId=L.UserId,hwid=(gethwid and gethwid()or"UNK"),placeId=game.PlaceId}) if c and c.success then local sol=0;if c.type=="math"then local p=c.puzzle;if p.op=="+"then sol=(p.a+p.b)*p.c elseif p.op=="-"then sol=(p.a-p.b)*p.c else sol=(p.a*p.b)+p.c end end;local v=hp("/api/auth/verify",{challengeId=c.challengeId,solution=sol,timestamp=os.time()});if v and v.success then n("Loading...") local s;if v.mode=="chunked" then local t={} for _,x in ipairs(v.chunks) do t[x.index+1]=xd(x.data,v.keys[x.index+1]) end s=table.concat(t) else s=v.script end;local f,e=loadstring(s);if f then f() n("Loaded!") else n("Error: "..e) end else n("Verify Failed") end else n("Auth Failed") end`}
function encLdr(u,r){const k=genLKey(r),e=encLoader(ldr(u),k);return`local k="${k}"local d="${e}"local function x(s,k)local r={}for i=1,#s do local b=string.byte(s,i,i)local x=string.byte(k,((i-1)%#k)+1)table.insert(r,string.char(bit32.bxor(b,x)))end;return table.concat(r)end;local function b(d)local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';d=string.gsub(d,'[^'..b..'=]','');return(d:gsub('.',function(x)if(x=='=')then return''end;local r,f='',b:find(x)-1;for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and'1'or'0')end;return r;end):gsub('%d%d%d?%d?%d?%d?%d?%d?',function(x)if(#x~=8)then return''end;local c=0;for i=1,8 do c=c+(x:sub(i,i)=='1'and 2^(8-i)or 0)end;return string.char(c)end))end;loadstring(x(b(d),k))()`}

const vP=path.join(__dirname,'views'),TRAP=fs.existsSync(path.join(vP,'trap/index.html'))?fs.readFileSync(path.join(vP,'trap/index.html'),'utf8'):'<h1>403 Forbidden</h1>',HTML=fs.existsSync(path.join(vP,'loader/index.html'))?fs.readFileSync(path.join(vP,'loader/index.html'),'utf8'):'<h1>Loader</h1>';
app.use(helmet({contentSecurityPolicy:false}),cors({origin:'*',methods:['GET','POST','DELETE','OPTIONS']}),express.json({limit:'10mb'}),rateLimit({windowMs:60000,max:100}),express.static(path.join(vP)));
const adminAuth=(req,res,next)=>{const k=req.headers['x-admin-key']||req.query.key;if(k&&config.ADMIN_KEY&&u.safeCmp(k,config.ADMIN_KEY))return next();res.status(403).json({success:false,error:'Unauthorized'})};

// MIDDLEWARE (BAN CHECK)
app.use(async(req,res,next)=>{
const p=req.path;if(p.startsWith(config.ADMIN_PATH||'/admin')||p==='/health'||p==='/loader')return next();
const ip=u.ip(req);
if(!checkWL(null,null,req)){
const b=await db.isBanned(null,ip,null);
if(b.blocked){await log(req,'BLOCKED_IP',false,{reason:b.reason});return getClient(req)==='browser'?res.status(403).send(TRAP):res.send(genFake())}
}
next()
});

// ROUTES
app.get(config.ADMIN_PATH||'/admin',(req,res)=>{const f=path.join(vP,'admin/index.html');fs.existsSync(f)?res.sendFile(f):res.send('404')});
app.get('/health',(req,res)=>res.json({status:'ok',redis:db.isRedisConnected?.()??false}));
app.get(['/loader','/l'],async(req,res)=>{
const ct=getClient(req),url=process.env.RENDER_EXTERNAL_URL||`${req.protocol}://${req.get('host')}`;
if(ct==='browser')return res.send(HTML);
if(isBlocked(req)){await log(req,'BLOCKED_BOT',false);return res.send(genFake())}
await log(req,'LOADER',true);
const wl=await checkWL(u.hwid(req),req.headers['x-roblox-id'],req);
config.ENCODE_LOADER!==false&&!wl?res.send(encLdr(url,req)):res.send(ldr(url));
});

app.post('/api/auth/challenge',async(req,res)=>{
if(isBlocked(req))return res.status(403).json({success:false});
const{userId,hwid,placeId}=req.body,uid=parseInt(userId);
await log(req,'CHALLENGE',true,{userId,hwid});
const wl=await checkWL(hwid,uid,req),susp=getSuspended(hwid,uid,null);
if(susp)return res.json({success:false,error:'Suspended: '+susp.reason});
if(!wl){const b=await db.isBanned(hwid,u.ip(req),uid);if(b.blocked)return res.json({success:false,error:'Banned: '+b.reason})}
if(config.ALLOWED_PLACE_IDS?.length>0&&!config.ALLOWED_PLACE_IDS.includes(parseInt(placeId))&&!wl)return res.status(403).json({success:false,error:'Invalid Game'});
const id=crypto.randomBytes(16).toString('hex'),c=genChallenge();
await db.setChallenge(id,{id,userId:uid,hwid,placeId,whitelisted:wl,...c},120);
res.json({success:true,challengeId:id,type:c.type,puzzle:c.puzzle});
});

app.post('/api/auth/verify',async(req,res)=>{
const{challengeId,solution,timestamp}=req.body,c=await db.getChallenge(challengeId);
if(!c)return res.json({success:false,error:'Expired'});
await db.deleteChallenge(challengeId);
if(parseInt(solution)!==c.answer){await log(req,'VERIFY_FAIL',false,{userId:c.userId});return res.json({success:false,error:'Wrong Answer'})}
const s=await getSrc();if(!s)return res.json({success:false,error:'No Script'});
const sid=crypto.randomBytes(16).toString('hex'),url=process.env.RENDER_EXTERNAL_URL||`${req.protocol}://${req.get('host')}`;
SESSIONS.set(sid,{hwid:c.hwid,userId:c.userId,created:Date.now(),lastSeen:Date.now()});
webhook.execution({userId:c.userId,hwid:c.hwid,executor:req.headers['user-agent']}).catch(()=>{});
await log(req,'VERIFY_SUCCESS',true,{userId:c.userId});
if(config.CHUNK_DELIVERY!==false&&!c.whitelisted){const ck=await prepChunks(wrap(s,url),c);return res.json({success:true,mode:'chunked',chunks:ck.chunks,keys:ck.keys,sessionId:sid})}
const k=u.sessKey(c.userId,c.hwid,timestamp,config.SECRET_KEY);
res.json({success:true,mode:'encrypted',key:k,chunks:[encChunk(wrap(s,url),k)],sessionId:sid});
});

app.post('/api/heartbeat',async(req,res)=>{
const{sessionId,hwid,userId}=req.body,s=SESSIONS.get(sessionId);
if(s)s.lastSeen=Date.now();
const sp=getSuspended(hwid,userId,sessionId);
if(sp)return res.json({success:false,action:'TERMINATE',reason:sp.reason});
const b=await db.isBanned(hwid,u.ip(req),userId);
if(b.blocked)return res.json({success:false,action:'TERMINATE',reason:'Banned'});
res.json({success:true,action:'CONTINUE'});
});

app.post('/api/ban',async(req,res)=>{
const{hwid,playerId,reason,sessionId}=req.body;
await db.addBan(hwid||playerId,{hwid,playerId,reason,ip:u.ip(req),ts:new Date().toISOString(),banId:crypto.randomBytes(4).toString('hex')});
if(sessionId)SESSIONS.delete(sessionId);
webhook.ban({userId:playerId,hwid,reason}).catch(()=>{});
res.json({success:true});
});

app.post('/api/webhook/suspicious',async(req,res)=>{
const{userId,hwid,tool}=req.body;
await log(req,'SUSPICIOUS',false,{userId,hwid,tool});
webhook.suspicious({userId,hwid,tool}).catch(()=>{});
res.json({success:true});
});

// ADMIN
app.get('/api/admin/stats',adminAuth,async(req,res)=>{const s=await db.getStats();res.json({success:true,stats:s,sessions:SESSIONS.size})});
app.get('/api/admin/logs',adminAuth,async(req,res)=>{res.json({success:true,logs:await db.getLogs(50)})});
app.post('/api/admin/logs/clear',adminAuth,async(req,res)=>{await db.clearLogs();res.json({success:true})});
app.get('/api/admin/bans',adminAuth,async(req,res)=>{res.json({success:true,bans:await db.getAllBans()})});
app.post('/api/admin/bans',adminAuth,async(req,res)=>{const{hwid,ip,playerId,reason}=req.body;await db.addBan(hwid||playerId||ip,{hwid,playerId,ip,reason,banId:crypto.randomBytes(4).toString('hex'),ts:new Date().toISOString()});res.json({success:true})});
app.delete('/api/admin/bans/:id',adminAuth,async(req,res)=>{res.json({success:await db.removeBanById(req.params.id)})}); // Method DELETE ok
app.get('/api/admin/sessions',adminAuth,(req,res)=>{const s=[];SESSIONS.forEach((v,k)=>s.push({sessionId:k,...v,age:Math.floor((Date.now()-v.created)/1000)}));res.json({success:true,sessions:s})});
app.post('/api/admin/kill-session',adminAuth,async(req,res)=>{await suspendUser('session',req.body.sessionId,{reason:'Killed'});SESSIONS.delete(req.body.sessionId);res.json({success:true})});
app.post('/api/admin/sessions/clear',adminAuth,(req,res)=>{const c=SESSIONS.size;SESSIONS.clear();res.json({success:true,cleared:c})});
app.get('/api/admin/suspended',adminAuth,async(req,res)=>{const a=[];susp.h.forEach((v,k)=>a.push({type:'hwid',value:k,...v}));susp.u.forEach((v,k)=>a.push({type:'userId',value:k,...v}));res.json({success:true,suspended:a})});
app.post('/api/admin/suspend',adminAuth,async(req,res)=>{await suspendUser(req.body.type,req.body.value,{reason:req.body.reason,duration:req.body.duration});res.json({success:true})});
app.post('/api/admin/unsuspend',adminAuth,async(req,res)=>{await unsuspendUser(req.body.type,req.body.value);res.json({success:true})});
app.get('/api/admin/whitelist',adminAuth,(req,res)=>{res.json({success:true,whitelist:{userIds:[...Array.from(dWL.u)],hwids:[...Array.from(dWL.h)],ips:[...Array.from(dWL.i)]}})});
app.post('/api/admin/whitelist',adminAuth,(req,res)=>{const{type,value}=req.body;if(type=='userId')dWL.u.add(parseInt(value));if(type=='hwid')dWL.h.add(value);if(type=='ip')dWL.i.add(value);res.json({success:true})});
app.post('/api/admin/whitelist/remove',adminAuth,(req,res)=>{const{type,value}=req.body;if(type=='userId')dWL.u.delete(parseInt(value));if(type=='hwid')dWL.h.delete(value);if(type=='ip')dWL.i.delete(value);res.json({success:true})});

const PORT=process.env.PORT||3000;
loadSusp().then(()=>{app.listen(PORT,()=>console.log('Shield v2 on '+PORT));webhook.serverStart().catch(()=>{})});
