const express=require('express'),axios=require('axios'),crypto=require('crypto'),cors=require('cors'),helmet=require('helmet'),rateLimit=require('express-rate-limit'),path=require('path'),fs=require('fs'),config=require('./config'),db=require('./lib/redis'),webhook=require('./lib/webhook');
const app=express(),SESSIONS=new Map(),dynamicWhitelist={userIds:new Set(),hwids:new Set()},suspendedUsers={hwids:new Map(),userIds:new Map(),sessions:new Map()};

// === CONSTANTS ===
const BOT_PATTERNS=['python','python-requests','aiohttp','httpx','curl','wget','libcurl','axios','node-fetch','got/','undici','superagent','java/','okhttp','apache-http','go-http','golang','ruby','perl','php/','postman','insomnia','paw/','bot','crawler','spider','scraper','slurp','googlebot','bingbot','yandex','facebookexternalhit','twitterbot','discordbot','telegrambot','burp','fiddler','charles','mitmproxy','nmap','nikto','sqlmap','nuclei','httpie','scanner','checker','monitor','probe'];
const BROWSER_HEADERS=['sec-fetch-dest','sec-fetch-mode','sec-fetch-site','sec-ch-ua','sec-ch-ua-mobile','upgrade-insecure-requests'];
const EXECUTOR_HEADERS=['x-hwid','x-roblox-id','x-place-id','x-job-id','x-session-id'];
const ALLOWED_EXECUTORS=['synapse','synapsex','script-ware','scriptware','delta','fluxus','krnl','oxygen','evon','hydrogen','vegax','trigon','comet','solara','wave','zorara','codex','celery','swift','sirhurt','electron','sentinel','coco','temple','valyse','nihon','jjsploit','arceus','roblox','wininet','win32'];

// === UTILITY FUNCTIONS ===
function sha256(s){return crypto.createHash('sha256').update(s).digest('hex')}
function hmac(d,k){return crypto.createHmac('sha256',k).update(d).digest('hex')}
function secureCompare(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;try{return crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b))}catch{return false}}
function getIP(r){return(r.headers['x-forwarded-for']||'').split(',')[0].trim()||r.headers['x-real-ip']||r.ip||'0.0.0.0'}
function getHWID(r){return r.headers['x-hwid']||null}
function genSessionKey(u,h,t,s){return hmac(`${u}:${h}:${t}`,s).substring(0,32)}

// === CLIENT DETECTION ===
function getClientType(req){const ua=(req.headers['user-agent']||'').toLowerCase(),headers=req.headers;const execScore=EXECUTOR_HEADERS.filter(h=>headers[h]).length;const browScore=BROWSER_HEADERS.filter(h=>headers[h]).length;const isBotUA=BOT_PATTERNS.some(p=>ua.includes(p));const isExecUA=ALLOWED_EXECUTORS.some(e=>ua.includes(e));if(isBotUA&&execScore===0)return'bot';if(browScore>=2)return'browser';if(!ua||ua.length<10){if(execScore>=2)return'executor';return'bot'}if(execScore>=2)return'executor';if(isExecUA)return'executor';if(ua.includes('mozilla')&&execScore===0&&!isExecUA){const accept=headers['accept']||'';if(accept.includes('text/html'))return'browser';return'unknown'}return'unknown'}
function shouldBlock(req){return['bot','browser','unknown'].includes(getClientType(req))}

// === FAKE SCRIPT GENERATOR ===
function genFakeScript(){const ts=Date.now(),rS=(l)=>{const c='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';let s=c[Math.floor(Math.random()*26)];for(let i=1;i<l;i++)s+=c[Math.floor(Math.random()*c.length)];return s},rH=(l)=>{let h='';for(let i=0;i<l;i++)h+=Math.floor(Math.random()*16).toString(16);return h},rN=(a,b)=>Math.floor(Math.random()*(b-a+1))+a;const v=Array(30).fill(0).map(()=>rS(rN(4,12)));const styles=[()=>`--[[ Luraph v${rN(12,15)}.${rN(0,9)}.${rN(0,9)} | ${rH(32)} ]]\nlocal ${v[0]},${v[1]},${v[2]};\nlocal ${v[4]}=(function()\nlocal ${v[5]}={${Array(rN(20,40)).fill(0).map(()=>`"\\${rN(100,255)}\\${rN(100,255)}"`).join(',')}};\nreturn 0x${rH(4)};\nend)();\nerror("Verification failed",0);`,()=>`--[=[ IronBrew2 ${rN(1,3)}.${rN(0,9)}${rN(0,9)} ]=]\nlocal ${v[0]}="${rH(64)}";\nlocal ${v[1]}=coroutine.wrap(function()\nwhile true do coroutine.yield(math.random(0,${rN(10000,99999)}));end\nend);\n--[=[ VM Encrypted ]=]`];return styles[Math.floor(Math.random()*styles.length)]()}

// === LOADER ENCRYPTION ===
function encryptLoader(script,key){const kB=Buffer.from(key),sB=Buffer.from(script),enc=[];for(let i=0;i<sB.length;i++)enc.push(sB[i]^kB[i%kB.length]);return Buffer.from(enc).toString('base64')}
function genLoaderKey(req){const c=[req.headers['x-hwid']||'',req.headers['x-roblox-id']||'',req.headers['x-place-id']||'',config.LOADER_KEY||config.SECRET_KEY];return crypto.createHash('md5').update(c.join(':')).digest('hex').substring(0,16)}

// === CHUNKED DELIVERY ===
function chunkString(str,size){const chunks=[];for(let i=0;i<str.length;i+=size)chunks.push(str.substring(i,i+size));return chunks}
function encryptChunk(chunk,key){const enc=[];for(let i=0;i<chunk.length;i++)enc.push(chunk.charCodeAt(i)^key.charCodeAt(i%key.length));return enc}
function generateChunkKeys(baseKey,count){const keys=[];for(let i=0;i<count;i++){keys.push(crypto.createHash('sha256').update(baseKey+':chunk:'+i+':'+Date.now()).digest('hex').substring(0,32))}return keys}
async function prepareChunkedScript(script,challenge){const chunkCount=config.CHUNK_COUNT||3;const chunkSize=Math.ceil(script.length/chunkCount);const chunks=chunkString(script,chunkSize);const baseKey=crypto.createHash('sha256').update(challenge.hwid+':'+challenge.userId+':'+config.SECRET_KEY).digest('hex');const chunkKeys=generateChunkKeys(baseKey,chunks.length);const encryptedChunks=chunks.map((chunk,i)=>({index:i,data:encryptChunk(chunk,chunkKeys[i]),keyHint:chunkKeys[i].substring(0,8)}));const assemblyKey=crypto.createHash('md5').update(chunkKeys.join(':')).digest('hex');return{chunks:encryptedChunks,keys:chunkKeys,assemblyKey,totalChunks:chunks.length}}

// === WHITELIST ===
async function checkWhitelist(hwid,userId){if(userId){const uid=parseInt(userId);if(config.WHITELIST_USER_IDS&&config.WHITELIST_USER_IDS.includes(uid))return true;if(dynamicWhitelist.userIds.has(uid))return true}if(hwid){if(config.WHITELIST_HWIDS&&config.WHITELIST_HWIDS.includes(hwid))return true;if(dynamicWhitelist.hwids.has(hwid))return true}return false}
function isOwner(userId){if(!userId)return false;const uid=parseInt(userId);return config.OWNER_USER_IDS&&config.OWNER_USER_IDS.includes(uid)}

// === SUSPEND/KILL SWITCH ===
async function suspendUser(type,value,data){const entry={...data,suspendedAt:new Date().toISOString(),expiresAt:data.duration?new Date(Date.now()+data.duration*1000).toISOString():null};if(type==='hwid')suspendedUsers.hwids.set(value,entry);else if(type==='userId')suspendedUsers.userIds.set(String(value),entry);else if(type==='session')suspendedUsers.sessions.set(value,entry);await db.addSuspend(type,value,entry);webhook.suspicious({userId:data.userId,hwid:data.hwid,ip:data.ip,reason:'Suspended: '+(data.reason||'Admin action'),tool:'N/A',action:'Suspended'}).catch(()=>{})}
async function unsuspendUser(type,value){if(type==='hwid')suspendedUsers.hwids.delete(value);else if(type==='userId')suspendedUsers.userIds.delete(String(value));else if(type==='session')suspendedUsers.sessions.delete(value);await db.removeSuspend(type,value)}
function checkSuspended(hwid,userId,sessionId){const now=Date.now();if(sessionId&&suspendedUsers.sessions.has(sessionId)){const s=suspendedUsers.sessions.get(sessionId);if(!s.expiresAt||new Date(s.expiresAt)>now)return{suspended:true,reason:s.reason||'Session suspended'};suspendedUsers.sessions.delete(sessionId)}if(hwid&&suspendedUsers.hwids.has(hwid)){const s=suspendedUsers.hwids.get(hwid);if(!s.expiresAt||new Date(s.expiresAt)>now)return{suspended:true,reason:s.reason||'Device suspended'};suspendedUsers.hwids.delete(hwid)}if(userId&&suspendedUsers.userIds.has(String(userId))){const s=suspendedUsers.userIds.get(String(userId));if(!s.expiresAt||new Date(s.expiresAt)>now)return{suspended:true,reason:s.reason||'User suspended'};suspendedUsers.userIds.delete(String(userId))}return{suspended:false}}
async function loadSuspendedFromDB(){const all=await db.getAllSuspends();if(all&&all.length>0){all.forEach(s=>{if(s.type==='hwid')suspendedUsers.hwids.set(s.value,s.data);else if(s.type==='userId')suspendedUsers.userIds.set(s.value,s.data);else if(s.type==='session')suspendedUsers.sessions.set(s.value,s.data)});console.log(`✅ Loaded ${all.length} suspended entries`)}}

// === LOGGING ===
async function logAccess(r,a,s,d={}){const log={ip:getIP(r),hwid:getHWID(r),ua:(r.headers['user-agent']||'').substring(0,100),action:a,success:s,path:r.path,client:getClientType(r),ts:new Date().toISOString(),...d};await db.addLog(log);return log}

// === CHALLENGE GENERATOR ===
function genChallenge(){const types=['math','bitwise','sequence','sum'],type=types[Math.floor(Math.random()*types.length)];switch(type){case'math':const op=['+','-','*'][Math.floor(Math.random()*3)],a=Math.floor(Math.random()*50)+10,b=Math.floor(Math.random()*20)+5,c=Math.floor(Math.random()*10)+1;let ans;if(op==='+')ans=(a+b)*c;else if(op==='-')ans=(a-b)*c;else ans=(a*b)+c;return{type:'math',puzzle:{a,b,c,op},answer:ans};case'bitwise':const x=Math.floor(Math.random()*200)+50,y=Math.floor(Math.random()*100)+20,bop=['xor','and','or'][Math.floor(Math.random()*3)];let bans;if(bop==='xor')bans=x^y;else if(bop==='and')bans=x&y;else bans=x|y;return{type:'bitwise',puzzle:{x,y,op:bop},answer:bans};case'sequence':const start=Math.floor(Math.random()*15)+1,step=Math.floor(Math.random()*8)+2;return{type:'sequence',puzzle:{seq:[start,start+step,start+step*2,start+step*3]},answer:start+step*4};default:const nums=Array.from({length:5},()=>Math.floor(Math.random()*50)+1);return{type:'sum',puzzle:{numbers:nums},answer:nums.reduce((a,b)=>a+b,0)}}}

// === SCRIPT HANDLING ===
function isObfuscated(s){if(!s)return false;return[/Luraph/i,/Moonsec/i,/IronBrew/i,/Prometheus/i,/PSU/i].some(r=>r.test(s.substring(0,500)))}
async function getScript(){const cached=await db.getCachedScript();if(cached)return cached;if(!config.SCRIPT_SOURCE_URL)return null;try{const res=await axios.get(config.SCRIPT_SOURCE_URL,{timeout:30000,headers:{'User-Agent':'Roblox/WinInet'},maxContentLength:50000000});if(typeof res.data==='string'&&res.data.length>50){await db.setCachedScript(res.data);return res.data}}catch(e){console.error('Script fetch error:',e.message)}return null}

// === SCRIPT WRAPPER WITH ANTI-SPY ===
function wrapScript(script,serverUrl){const o=(config.OWNER_USER_IDS||[]).join(',');const w=(config.WHITELIST_USER_IDS||[]).join(',');const sid=crypto.randomBytes(16).toString('hex');const antiSpyEnabled=config.ANTI_SPY_ENABLED!==false;const autoBan=config.AUTO_BAN_SPYTOOLS===true;
return`--[[ Script Shield Protection Layer v2 ]]
local _CFG={owners={${o}},whitelist={${w}},banUrl="${serverUrl}/api/ban",webhookUrl="${serverUrl}/api/webhook/suspicious",heartbeatUrl="${serverUrl}/api/heartbeat",sessionId="${sid}",antiSpy=${antiSpyEnabled},autoBan=${autoBan},heartbeatInterval=45}
local _P=game:GetService("Players")
local _L=_P.LocalPlayer
local _CG=game:GetService("CoreGui")
local _SG=game:GetService("StarterGui")
local _H=game:GetService("HttpService")
local _A=true
local _CON={}
local _HB_FAIL=0
local function _n(t,x,d)pcall(function()_SG:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3})end)end
local function _hw()local s,r=pcall(function()if gethwid then return gethwid()end;if getexecutorname then return getexecutorname()..tostring(_L.UserId)end;return"NK_"..tostring(_L.UserId)end)return s and r or"UNK"end
local function _hp(u,d)local r=(syn and syn.request)or request or http_request or(http and http.request)if not r then return nil end;local s,res=pcall(function()return r({Url=u,Method="POST",Headers={["Content-Type"]="application/json",["User-Agent"]="Roblox/WinInet",["x-hwid"]=_hw(),["x-roblox-id"]=tostring(_L.UserId),["x-session-id"]=_CFG.sessionId},Body=_H:JSONEncode(d)})end)if not s or not res then return nil end;if res.StatusCode~=200 then return nil end;local ps,pd=pcall(function()return _H:JSONDecode(res.Body)end)return ps and pd or nil end
local function _isW(u)for _,i in ipairs(_CFG.whitelist)do if u==i then return true end end;return false end
local function _isO(u)for _,i in ipairs(_CFG.owners)do if u==i then return true end end;return false end
local function _cl(msg)if not _A then return end;_A=false;_n("⚠️",msg or"Script terminated",3);for i=#_CON,1,-1 do pcall(function()_CON[i]:Disconnect()end)end;task.wait(0.5);_L:Kick(msg or"Session terminated")end
local _SPY_TOOLS={"SimpleSpy","HttpSpy","RemoteSpy","Hydroxide","Dex","DarkDex","InfiniteYield","CMD-X","ServerSpy","ScriptDumper"}
local _SPY_GUIS={"simplespy","httpspy","remotespy","hydroxide","dex","darkdex","infiniteyield","cmdx","serverspy"}
local _SNAP_GUIS={}
local _SNAP_GLOBALS={}
local function _takeSnapshot()local e=getgenv and getgenv()or _G;for _,name in ipairs(_SPY_TOOLS)do if rawget(e,name)then _SNAP_GLOBALS[name]=true end end;pcall(function()for _,g in pairs(_CG:GetChildren())do if g:IsA("ScreenGui")then _SNAP_GUIS[g.Name:lower()]=true end end end)end
local function _detectNewSpy()if _isW(_L.UserId)then return nil end;local e=getgenv and getgenv()or _G;for _,name in ipairs(_SPY_TOOLS)do local ok,v=pcall(function()return rawget(e,name)end)if ok and v and not _SNAP_GLOBALS[name]then return name end end;pcall(function()for _,g in pairs(_CG:GetChildren())do if g:IsA("ScreenGui")then local n=g.Name:lower()for _,spy in ipairs(_SPY_GUIS)do if n:find(spy)and not _SNAP_GUIS[n]then return g.Name end end end end end)return nil end
local function _startAntiSpy()if not _CFG.antiSpy or _isW(_L.UserId)then return end;task.spawn(function()task.wait(2);_takeSnapshot();task.wait(1);_takeSnapshot();while _A do task.wait(20);if not _A then break end;local tool=_detectNewSpy()if tool then pcall(function()_hp(_CFG.webhookUrl,{userId=_L.UserId,hwid=_hw(),tool=tool,sessionId=_CFG.sessionId})end)if _CFG.autoBan then pcall(function()_hp(_CFG.banUrl,{hwid=_hw(),playerId=_L.UserId,reason="Spy tool: "..tool,sessionId=_CFG.sessionId})end)end;_cl("Security violation: "..tool)break end end end)end
local function _startHeartbeat()task.spawn(function()task.wait(10)while _A do local res=_hp(_CFG.heartbeatUrl,{sessionId=_CFG.sessionId,hwid=_hw(),userId=_L.UserId})if res then _HB_FAIL=0;if res.action=="TERMINATE"then _cl(res.reason or"Session terminated by admin")break elseif res.action=="KICK"then _cl(res.reason or"Kicked by admin")break elseif res.action=="MESSAGE"and res.message then _n("📢",res.message,5)end else _HB_FAIL=_HB_FAIL+1;if _HB_FAIL>=5 then _cl("Connection lost")break end end;task.wait(_CFG.heartbeatInterval)end end)end
local function _checkOwner()for _,p in pairs(_P:GetPlayers())do if _isO(p.UserId)and p~=_L then return false end end;return true end
local function _startOwnerMonitor()table.insert(_CON,_P.PlayerAdded:Connect(function(p)task.wait(1)if _isO(p.UserId)then _cl("Owner joined server")end end))end
if not _checkOwner()then _n("⚠️","Owner in server",3)return end
_startOwnerMonitor()
_startAntiSpy()
_startHeartbeat()
${script}`}

// === LOADER ===
function getLoader(url){return`local S="${url}"local H=game:GetService("HttpService")local P=game:GetService("Players")local G=game:GetService("StarterGui")local L=P.LocalPlayer local function n(t,x,d)pcall(function()G:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3})end)end local function hw()local s,r=pcall(function()if gethwid then return gethwid()end;if getexecutorname then return getexecutorname()..tostring(L.UserId)end;return"NK_"..tostring(L.UserId)end)return s and r or"UNK"end local function hp(u,d)local r=(syn and syn.request)or request or http_request or(http and http.request)if not r then return nil end;local s,res=pcall(function()return r({Url=u,Method="POST",Headers={["Content-Type"]="application/json",["User-Agent"]="Roblox/WinInet",["x-hwid"]=hw(),["x-roblox-id"]=tostring(L.UserId),["x-place-id"]=tostring(game.PlaceId),["x-job-id"]=game.JobId},Body=H:JSONEncode(d)})end)if not s or not res or res.StatusCode~=200 then return nil end;local ps,pd=pcall(function()return H:JSONDecode(res.Body)end)return ps and pd or nil end local function xd(d,k)local r={}for i=1,#d do r[i]=string.char(bit32.bxor(d[i],k:byte((i-1)%#k+1)))end;return table.concat(r)end local function sv(p)if not p or not p.type then return 0 end;if p.type=="math"then local a,b,c,op=p.puzzle.a,p.puzzle.b,p.puzzle.c,p.puzzle.op;if op=="+"then return(a+b)*c elseif op=="-"then return(a-b)*c else return(a*b)+c end elseif p.type=="bitwise"then local x,y,op=p.puzzle.x,p.puzzle.y,p.puzzle.op;if op=="xor"then return bit32.bxor(x,y)elseif op=="and"then return bit32.band(x,y)else return bit32.bor(x,y)end elseif p.type=="sequence"then local s=p.puzzle.seq;return s[4]+(s[2]-s[1])elseif p.puzzle and p.puzzle.numbers then local sum=0;for _,x in ipairs(p.puzzle.numbers)do sum=sum+x end;return sum end;return 0 end local function asm(data)if data.mode=="raw"then return data.script elseif data.mode=="chunked"then local parts={}for i,chunk in ipairs(data.chunks)do local key=data.keys[chunk.index+1]parts[chunk.index+1]=xd(chunk.data,key)end;return table.concat(parts)elseif data.mode=="encrypted"then local p={}for i,ch in ipairs(data.chunks)do p[i]=xd(ch,data.key)end;return table.concat(p)end;return nil end n("🔄","Connecting...",2)local c=hp(S.."/api/auth/challenge",{userId=L.UserId,hwid=hw(),placeId=game.PlaceId})if not c or not c.success then n("❌",c and c.error or"Failed",5)return end n("🔐","Verifying...",2)local v=hp(S.."/api/auth/verify",{challengeId=c.challengeId,solution=sv(c),timestamp=os.time()})if not v or not v.success then n("❌",v and v.error or"Failed",5)return end n("📦","Loading...",2)local fs=asm(v)if not fs then n("❌","Assembly failed",5)return end n("✅","Success!",1)local fn,err=loadstring(fs)if fn then fs=nil;v=nil;c=nil;pcall(fn)else n("❌","Error",5)end`}
function getEncodedLoader(url,req){const key=genLoaderKey(req),enc=encryptLoader(getLoader(url),key);return`local k="${key}"local d="${enc}"local function x(s,k)local r={}local b={}for i=1,#s do b[i]=s:byte(i)end;for i=1,#b do r[i]=string.char(bit32.bxor(b[i],k:byte((i-1)%#k+1)))end;return table.concat(r)end;local function b(s)local t={}local c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"for i=1,64 do t[c:sub(i,i)]=i-1 end;s=s:gsub("[^"..c.."=]","")local r={}local n=1;for i=1,#s,4 do local a,b,c,d=t[s:sub(i,i)]or 0,t[s:sub(i+1,i+1)]or 0,t[s:sub(i+2,i+2)]or 0,t[s:sub(i+3,i+3)]or 0;local v=a*262144+b*4096+c*64+d;r[n]=string.char(bit32.rshift(v,16)%256)n=n+1;if s:sub(i+2,i+2)~="="then r[n]=string.char(bit32.rshift(v,8)%256)n=n+1 end;if s:sub(i+3,i+3)~="="then r[n]=string.char(v%256)n=n+1 end end;return table.concat(r)end;loadstring(x(b(d),k))()`}

// === VIEWS PATH ===
const viewsPath=path.join(__dirname,'views');
const TRAP_HTML=fs.existsSync(path.join(viewsPath,'trap/index.html'))?fs.readFileSync(path.join(viewsPath,'trap/index.html'),'utf8'):`<!DOCTYPE html><html><head><title>403</title></head><body style="background:#0a0a0f;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif"><div style="text-align:center"><h1 style="font-size:60px">🛡️</h1><h2 style="color:#ef4444">Access Denied</h2></div></body></html>`;

// === MIDDLEWARE ===
app.use(helmet({contentSecurityPolicy:false,crossOriginEmbedderPolicy:false,crossOriginResourcePolicy:false}));
app.use(cors({origin:'*',methods:['GET','POST','DELETE','OPTIONS'],allowedHeaders:['Content-Type','x-admin-key','x-hwid','x-roblox-id','x-place-id','x-job-id','x-session-id']}));
app.use(express.json({limit:'10mb'}));
app.set('trust proxy',1);
app.use(rateLimit({windowMs:60000,max:100,keyGenerator:r=>getIP(r)}));
app.use('/admin/css',express.static(path.join(viewsPath,'admin/css')));
app.use('/admin/js',express.static(path.join(viewsPath,'admin/js')));
app.use(async(req,res,next)=>{const ban=await db.isBanned(null,getIP(req),null);if(ban.blocked){const ct=getClientType(req);if(ct==='browser')return res.status(403).type('html').send(TRAP_HTML);return res.status(403).type('text/plain').send(genFakeScript())}next()});

// === ADMIN AUTH ===
const adminAuth=(req,res,next)=>{const key=req.headers['x-admin-key']||req.query.key;if(!key)return res.status(403).json({success:false,error:'Unauthorized'});if(!config.ADMIN_KEY)return res.status(500).json({success:false,error:'Server misconfigured'});if(!secureCompare(key,config.ADMIN_KEY))return res.status(403).json({success:false,error:'Unauthorized'});next()};

// === PUBLIC ROUTES ===
app.get('/admin',(req,res)=>{const f=path.join(viewsPath,'admin/index.html');if(fs.existsSync(f))res.sendFile(f);else res.status(404).send('Not found')});
app.get('/',(req,res)=>{const ct=getClientType(req);if(ct==='browser')return res.status(403).type('html').send(TRAP_HTML);if(shouldBlock(req))return res.status(403).type('text/plain').send(genFakeScript());res.json({status:'ok',v:'2.0.0'})});
app.get('/health',(req,res)=>res.json({status:'ok',redis:db.isRedisConnected?.()??false}));

// === LOADER ===
app.get(['/loader','/api/loader.lua','/api/loader','/l'],async(req,res)=>{const ct=getClientType(req),ip=getIP(req),hwid=getHWID(req);await logAccess(req,'LOADER',ct==='executor',{clientType:ct});if(shouldBlock(req)){console.log(`[Loader] Blocked ${ct} from ${ip}`);return res.status(200).type('text/plain').send(genFakeScript())}const userId=req.headers['x-roblox-id'];const isWL=await checkWhitelist(hwid,userId);const url=process.env.RENDER_EXTERNAL_URL||`${req.protocol}://${req.get('host')}`;if(config.ENCODE_LOADER!==false&&!isWL){res.type('text/plain').send(getEncodedLoader(url,req))}else{res.type('text/plain').send(getLoader(url))}});

// === AUTH CHALLENGE ===
app.post('/api/auth/challenge',async(req,res)=>{const ct=getClientType(req);if(shouldBlock(req)){await logAccess(req,'CHALLENGE_BLOCKED',false,{clientType:ct});return res.status(403).json({success:false,error:'Access denied'})}const{userId,hwid,placeId}=req.body;if(!userId||!placeId)return res.status(400).json({success:false,error:'Missing fields'});if(config.REQUIRE_HWID&&!hwid)return res.status(400).json({success:false,error:'HWID required'});const uid=parseInt(userId),pid=parseInt(placeId);if(isNaN(uid)||isNaN(pid))return res.status(400).json({success:false,error:'Invalid format'});const ip=getIP(req);const isWL=await checkWhitelist(hwid,uid);const susp=checkSuspended(hwid,uid,null);if(susp.suspended)return res.status(403).json({success:false,error:'Suspended: '+susp.reason});if(!isWL){const ban=await db.isBanned(hwid,ip,uid);if(ban.blocked)return res.status(403).json({success:false,error:'Banned: '+ban.reason})}if(config.ALLOWED_PLACE_IDS&&config.ALLOWED_PLACE_IDS.length>0&&!config.ALLOWED_PLACE_IDS.includes(pid)&&!isWL){return res.status(403).json({success:false,error:'Game not authorized'})}await logAccess(req,'CHALLENGE',true,{clientType:ct,whitelisted:isWL,userId:uid});const id=crypto.randomBytes(16).toString('hex'),chal=genChallenge();await db.setChallenge(id,{id,userId:uid,hwid:hwid||'none',placeId:pid,ip,whitelisted:isWL,...chal},120);res.json({success:true,challengeId:id,type:chal.type,puzzle:chal.puzzle,expiresIn:120})});

// === AUTH VERIFY ===
app.post('/api/auth/verify',async(req,res)=>{const ct=getClientType(req);if(shouldBlock(req))return res.status(403).json({success:false,error:'Access denied'});const{challengeId,solution,timestamp}=req.body;if(!challengeId||solution===undefined||!timestamp)return res.status(400).json({success:false,error:'Missing fields'});const challenge=await db.getChallenge(challengeId);if(!challenge)return res.status(403).json({success:false,error:'Challenge expired'});if(challenge.ip!==getIP(req))return res.status(403).json({success:false,error:'IP mismatch'});if(parseInt(solution)!==challenge.answer)return res.status(403).json({success:false,error:'Wrong solution'});await db.deleteChallenge(challengeId);const script=await getScript();if(!script)return res.status(500).json({success:false,error:'Script not configured'});const url=process.env.RENDER_EXTERNAL_URL||`${req.protocol}://${req.get('host')}`;const wrapped=wrapScript(script,url);const sessionId=crypto.randomBytes(16).toString('hex');SESSIONS.set(sessionId,{hwid:challenge.hwid,ip:challenge.ip,userId:challenge.userId,placeId:challenge.placeId,created:Date.now(),lastSeen:Date.now()});
webhook.execution({userId:challenge.userId,hwid:challenge.hwid,placeId:challenge.placeId,ip:challenge.ip,executor:req.headers['user-agent']}).catch(()=>{});
await logAccess(req,'VERIFY_SUCCESS',true,{userId:challenge.userId});
if(config.CHUNK_DELIVERY!==false&&!challenge.whitelisted){const chunked=await prepareChunkedScript(wrapped,challenge);return res.json({success:true,mode:'chunked',chunks:chunked.chunks,keys:chunked.keys,assemblyKey:chunked.assemblyKey,totalChunks:chunked.totalChunks,sessionId})}
const isObf=config.SCRIPT_ALREADY_OBFUSCATED||isObfuscated(script);if(isObf)return res.json({success:true,mode:'raw',script:wrapped,sessionId});
const key=genSessionKey(challenge.userId,challenge.hwid,timestamp,config.SECRET_KEY);const chunks=[];for(let i=0;i<wrapped.length;i+=1500){const chunk=wrapped.substring(i,i+1500),enc=[];for(let j=0;j<chunk.length;j++)enc.push(chunk.charCodeAt(j)^key.charCodeAt(j%key.length));chunks.push(enc)}res.json({success:true,mode:'encrypted',key,chunks,sessionId})});

// === HEARTBEAT (Kill Switch Check) ===
app.post('/api/heartbeat',async(req,res)=>{const{sessionId,hwid,userId}=req.body;if(!sessionId)return res.json({success:true,action:'CONTINUE'});const session=SESSIONS.get(sessionId);if(session)session.lastSeen=Date.now();const susp=checkSuspended(hwid,userId,sessionId);if(susp.suspended){if(session)SESSIONS.delete(sessionId);return res.json({success:false,action:'TERMINATE',reason:susp.reason})}const ban=await db.isBanned(hwid,getIP(req),userId);if(ban.blocked){if(session)SESSIONS.delete(sessionId);return res.json({success:false,action:'TERMINATE',reason:'Banned: '+ban.reason})}res.json({success:true,action:'CONTINUE'})});

// === WEBHOOK SUSPICIOUS ===
app.post('/api/webhook/suspicious',async(req,res)=>{const{userId,hwid,tool,sessionId}=req.body;await logAccess(req,'SUSPICIOUS',false,{userId,hwid,tool});webhook.suspicious({userId,hwid,ip:getIP(req),reason:'Spy tool detected',tool,action:config.AUTO_BAN_SPYTOOLS?'Auto-banned':'Kicked'}).catch(()=>{});res.json({success:true})});

// === BAN ===
app.post('/api/ban',async(req,res)=>{const{hwid,playerId,reason,sessionId}=req.body;if(!hwid&&!playerId)return res.status(400).json({error:'Missing id'});const banId=crypto.randomBytes(8).toString('hex').toUpperCase();const banData={ip:getIP(req),reason:reason||'Auto',banId,ts:new Date().toISOString()};if(hwid)await db.addBan(hwid,{hwid,...banData});if(playerId)await db.addBan(String(playerId),{playerId,...banData});if(sessionId)SESSIONS.delete(sessionId);await logAccess(req,'BAN_ADDED',true,{hwid,playerId,reason});webhook.ban({userId:playerId,hwid,ip:getIP(req),reason,bannedBy:'System',banId}).catch(()=>{});res.json({success:true,banId})});

// === ADMIN API ===
app.get('/api/admin/stats',adminAuth,async(req,res)=>{try{const stats=await db.getStats();const suspendCount=suspendedUsers.hwids.size+suspendedUsers.userIds.size+suspendedUsers.sessions.size;res.json({success:true,stats:{...stats,suspended:suspendCount},sessions:SESSIONS.size,ts:new Date().toISOString()})}catch(e){res.status(500).json({success:false,error:'Failed'})}});
app.get('/api/admin/logs',adminAuth,async(req,res)=>{const limit=Math.min(parseInt(req.query.limit)||50,500);const logs=await db.getLogs(limit);res.json({success:true,logs})});
app.get('/api/admin/bans',adminAuth,async(req,res)=>{const bans=await db.getAllBans();res.json({success:true,bans})});
app.post('/api/admin/bans',adminAuth,async(req,res)=>{const{hwid,ip,playerId,reason}=req.body;if(!hwid&&!ip&&!playerId)return res.status(400).json({success:false,error:'Required'});const banId=crypto.randomBytes(8).toString('hex').toUpperCase();const data={reason:reason||'Manual',banId,ts:new Date().toISOString()};if(hwid)await db.addBan(hwid,{hwid,...data});if(playerId)await db.addBan(String(playerId),{playerId,...data});if(ip)await db.addBan(ip,{ip,...data});webhook.ban({userId:playerId,hwid,ip,reason,bannedBy:'Admin',banId}).catch(()=>{});res.json({success:true,banId})});
app.delete('/api/admin/bans/:id',adminAuth,async(req,res)=>{const removed=await db.removeBanById(req.params.id);res.json({success:removed})});
app.post('/api/admin/bans/clear',adminAuth,async(req,res)=>{const count=await db.clearBans();res.json({success:true,cleared:count})});
app.post('/api/admin/cache/clear',adminAuth,async(req,res)=>{await db.setCachedScript(null);res.json({success:true})});
app.post('/api/admin/sessions/clear',adminAuth,async(req,res)=>{const count=SESSIONS.size;SESSIONS.clear();res.json({success:true,cleared:count})});

// === ADMIN WHITELIST ===
app.get('/api/admin/whitelist',adminAuth,async(req,res)=>{
res.json({success:true,whitelist:{
userIds:[...(config.WHITELIST_USER_IDS||[]),...Array.from(dynamicWhitelist.userIds)],
hwids:[...(config.WHITELIST_HWIDS||[]),...Array.from(dynamicWhitelist.hwids)],
owners:config.OWNER_USER_IDS||[]
}});
});

app.post('/api/admin/whitelist',adminAuth,async(req,res)=>{
const{type,value}=req.body;
if(!type||!value)return res.status(400).json({success:false,error:'Missing fields'});
if(type==='userId'){dynamicWhitelist.userIds.add(parseInt(value))}
else if(type==='hwid'){dynamicWhitelist.hwids.add(String(value))}
else{return res.status(400).json({success:false,error:'Invalid type'})}
res.json({success:true,msg:`Added ${type}: ${value}`});
});

app.post('/api/admin/whitelist/remove',adminAuth,async(req,res)=>{
const{type,value}=req.body;
if(!type||!value)return res.status(400).json({success:false,error:'Missing fields'});
if(type==='userId'){dynamicWhitelist.userIds.delete(parseInt(value))}
else if(type==='hwid'){dynamicWhitelist.hwids.delete(String(value))}
res.json({success:true,msg:`Removed ${type}: ${value}`});
});

// === ADMIN SUSPEND ===
app.get('/api/admin/suspended',adminAuth,async(req,res)=>{
const all=[];
suspendedUsers.hwids.forEach((v,k)=>all.push({type:'hwid',value:k,...v}));
suspendedUsers.userIds.forEach((v,k)=>all.push({type:'userId',value:k,...v}));
suspendedUsers.sessions.forEach((v,k)=>all.push({type:'session',value:k,...v}));
res.json({success:true,suspended:all});
});

app.post('/api/admin/suspend',adminAuth,async(req,res)=>{
const{type,value,reason,duration}=req.body;
if(!type||!value)return res.status(400).json({success:false,error:'Missing type or value'});
if(!['hwid','userId','session'].includes(type))return res.status(400).json({success:false,error:'Invalid type'});
const data={
reason:reason||'Suspended by admin',
expiresAt:duration?new Date(Date.now()+parseInt(duration)*1000).toISOString():null,
suspendedAt:new Date().toISOString()
};
if(type==='hwid')suspendedUsers.hwids.set(String(value),data);
else if(type==='userId')suspendedUsers.userIds.set(String(value),data);
else if(type==='session')suspendedUsers.sessions.set(String(value),data);
await db.addSuspend(type,String(value),data);
res.json({success:true,msg:`Suspended ${type}: ${value}${duration?' for '+duration+'s':' permanently'}`});
});

app.post('/api/admin/unsuspend',adminAuth,async(req,res)=>{
const{type,value}=req.body;
if(!type||!value)return res.status(400).json({success:false,error:'Missing fields'});
if(type==='hwid')suspendedUsers.hwids.delete(String(value));
else if(type==='userId')suspendedUsers.userIds.delete(String(value));
else if(type==='session')suspendedUsers.sessions.delete(String(value));
await db.removeSuspend(type,String(value));
res.json({success:true,msg:`Unsuspended ${type}: ${value}`});
});

app.post('/api/admin/kill-session',adminAuth,async(req,res)=>{
const{sessionId,reason}=req.body;
if(!sessionId)return res.status(400).json({success:false,error:'Missing sessionId'});
const session=SESSIONS.get(sessionId);
if(!session)return res.status(404).json({success:false,error:'Session not found'});
const data={reason:reason||'Killed by admin',suspendedAt:new Date().toISOString(),expiresAt:null};
suspendedUsers.sessions.set(sessionId,data);
await db.addSuspend('session',sessionId,data);
res.json({success:true,msg:'Session will be terminated'});
});

app.get('/api/admin/sessions',adminAuth,async(req,res)=>{
const sessions=[];
SESSIONS.forEach((v,k)=>sessions.push({sessionId:k,...v,age:Math.floor((Date.now()-v.created)/1000)}));
res.json({success:true,sessions:sessions.sort((a,b)=>b.created-a.created)});
});
// === 404 ===
app.use('*',(req,res)=>{const ct=getClientType(req);if(ct==='browser')return res.status(404).type('html').send(TRAP_HTML);if(shouldBlock(req))return res.status(403).type('text/plain').send(genFakeScript());res.status(404).json({error:'Not found'})});

// === CLEANUP ===
setInterval(()=>{const now=Date.now();for(const[k,v]of SESSIONS)if(now-v.lastSeen>7200000)SESSIONS.delete(k);const checkExpiry=(map)=>{for(const[k,v]of map)if(v.expiresAt&&new Date(v.expiresAt)<now)map.delete(k)};checkExpiry(suspendedUsers.hwids);checkExpiry(suspendedUsers.userIds);checkExpiry(suspendedUsers.sessions)},300000);

// === START ===
const PORT=process.env.PORT||config.PORT||3000;
loadSuspendedFromDB().then(()=>{webhook.serverStart().catch(()=>{});app.listen(PORT,'0.0.0.0',()=>{console.log(`\n🛡️ Script Shield v2.0 running on port ${PORT}\n📍 Admin: http://localhost:${PORT}/admin\n📦 Loader: http://localhost:${PORT}/loader\n`)})});
