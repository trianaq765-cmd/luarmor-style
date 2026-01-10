const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const config = require('./config');
const db = require('./lib/redis');
const webhook = require('./lib/webhook');

const app = express();
const SESSIONS = new Map();
const dynamicWhitelist = { userIds: new Set(), hwids: new Set(), ips: new Set() };
const suspendedUsers = { hwids: new Map(), userIds: new Map(), sessions: new Map() };

const BOT_PATTERNS = ['python', 'python-requests', 'aiohttp', 'httpx', 'curl', 'wget', 'libcurl', 'axios', 'node-fetch', 'got/', 'undici', 'superagent', 'java/', 'okhttp', 'apache-http', 'go-http', 'golang', 'ruby', 'perl', 'php/', 'postman', 'insomnia', 'paw/', 'bot', 'crawler', 'spider', 'scraper', 'slurp', 'googlebot', 'bingbot', 'yandex', 'facebookexternalhit', 'twitterbot', 'discordbot', 'telegrambot', 'burp', 'fiddler', 'charles', 'mitmproxy', 'nmap', 'nikto', 'sqlmap', 'nuclei', 'httpie', 'scanner', 'checker', 'monitor', 'probe'];
const B_HEADERS = ['sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-ch-ua', 'sec-ch-ua-mobile', 'upgrade-insecure-requests'];
const E_HEADERS = ['x-hwid', 'x-roblox-id', 'x-place-id', 'x-job-id', 'x-session-id'];
const ALLOWED_E = ['synapse', 'synapsex', 'script-ware', 'scriptware', 'delta', 'fluxus', 'krnl', 'oxygen', 'evon', 'hydrogen', 'vegax', 'trigon', 'comet', 'solara', 'wave', 'zorara', 'codex', 'celery', 'swift', 'sirhurt', 'electron', 'sentinel', 'coco', 'temple', 'valyse', 'nihon', 'jjsploit', 'arceus', 'roblox', 'wininet', 'win32'];

function hmac(d, k) { return crypto.createHmac('sha256', k).update(d).digest('hex'); }
function secureCompare(a, b) { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; } }
function getIP(r) { return (r.headers['x-forwarded-for'] || '').split(',')[0].trim() || r.headers['x-real-ip'] || r.ip || '0.0.0.0'; }
function getHWID(r) { return r.headers['x-hwid'] || null; }
function genSessionKey(u, h, t, s) { return hmac(`${u}:${h}:${t}`, s).substring(0, 32); }

function getClientType(req) {
const ua = (req.headers['user-agent'] || '').toLowerCase();
const h = req.headers;
const eS = E_HEADERS.filter(x => h[x]).length;
const bS = B_HEADERS.filter(x => h[x]).length;
if (BOT_PATTERNS.some(p => ua.includes(p)) && eS === 0) return 'bot';
if (bS >= 2) return 'browser';
if (!ua || ua.length < 10) return eS >= 2 ? 'executor' : 'bot';
if (eS >= 2 || ALLOWED_E.some(e => ua.includes(e))) return 'executor';
return 'unknown';
}

async function checkWhitelist(h, u, req) {
const ip = getIP(req);
if (config.WHITELIST_IPS?.includes(ip) || dynamicWhitelist.ips.has(ip)) return true;
if (u) { const uid = parseInt(u); if (config.WHITELIST_USER_IDS?.includes(uid) || dynamicWhitelist.userIds.has(uid)) return true; }
if (h && (config.WHITELIST_HWIDS?.includes(String(h)) || dynamicWhitelist.hwids.has(String(h)))) return true;
return false;
}

function shouldBlock(req) {
if (req.path === '/health') return false;
const ip = getIP(req);
if (config.WHITELIST_IPS?.includes(ip) || dynamicWhitelist.ips.has(ip)) return false;
const ua = (req.headers['user-agent'] || '').toLowerCase();
if (['uptimerobot', 'uptime-kuma', 'better uptime', 'googlebot'].some(b => ua.includes(b))) return false;
return ['bot', 'browser', 'unknown'].includes(getClientType(req));
}

function genFakeScript() {
const rS = (l) => { const c = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'; let s = ''; for (let i = 0; i < l; i++) s += c[Math.floor(Math.random() * c.length)]; return s; };
const rH = (l) => { let h = ''; for (let i = 0; i < l; i++) h += Math.floor(Math.random() * 16).toString(16); return h; };
return `--[[ Protected by Script Shield v2.0 | Hash: ${rH(32)} ]]\nlocal ${rS(6)} = "${rS(32)}";\nlocal ${rS(5)} = function(${rS(4)})\n return string.byte(${rS(4)}) * ${Math.floor(Math.random() * 100)};\nend;\n--[[ Obfuscation applied ]]`;
}

function encryptLoader(script, key) {
const kB = Buffer.from(key); const sB = Buffer.from(script); const enc = [];
for (let i = 0; i < sB.length; i++) enc.push(sB[i] ^ kB[i % kB.length]);
return Buffer.from(enc).toString('base64');
}

function genLoaderKey(req) {
const c = [req.headers['x-hwid'] || '', req.headers['x-roblox-id'] || '', req.headers['x-place-id'] || '', config.LOADER_KEY || config.SECRET_KEY];
return crypto.createHash('md5').update(c.join(':')).digest('hex').substring(0, 16);
}

function chunkString(str, size) { const chunks = []; for (let i = 0; i < str.length; i += size) chunks.push(str.substring(i, i + size)); return chunks; }

function encryptChunk(c, k) { const e = []; for (let i = 0; i < c.length; i++) { e.push((c.charCodeAt(i) ^ k.charCodeAt(i % k.length)) & 255); } return e; }

function generateChunkKeys(baseKey, count) { const keys = []; for (let i = 0; i < count; i++) keys.push(crypto.createHash('md5').update(baseKey + ':' + i).digest('hex')); return keys; }

async function prepareChunks(s, ch) {
const count = config.CHUNK_COUNT || 3; const size = Math.ceil(s.length / count); const chunks = chunkString(s, size);
const base = crypto.createHash('sha256').update((ch.hwid || '') + (ch.userId || '') + config.SECRET_KEY).digest('hex');
const keys = generateChunkKeys(base, chunks.length);
return { chunks: chunks.map((c, i) => ({ index: i, data: encryptChunk(c, keys[i]) })), keys, totalChunks: chunks.length };
}

async function suspendUser(type, value, data) {
const entry = { ...data, type, value, suspendedAt: new Date().toISOString(), expiresAt: data.duration ? new Date(Date.now() + parseInt(data.duration) * 1000).toISOString() : null };
if (type === 'hwid') suspendedUsers.hwids.set(String(value), entry);
else if (type === 'userId') suspendedUsers.userIds.set(String(value), entry);
else if (type === 'session') suspendedUsers.sessions.set(String(value), entry);
await db.addSuspend(type, String(value), entry);
}

function checkSuspended(h, u, sid) {
const now = Date.now();
const check = (m, k) => { if (m.has(k)) { const s = m.get(k); if (!s.expiresAt || new Date(s.expiresAt).getTime() > now) return { suspended: true, reason: s.reason || 'Suspended' }; m.delete(k); } return null; };
return check(suspendedUsers.sessions, sid) || check(suspendedUsers.hwids, h) || check(suspendedUsers.userIds, String(u));
}

async function loadSuspendedFromDB() {
const all = await db.getAllSuspends();
if (all && all.length > 0) { all.forEach(s => { if (s.type === 'hwid') suspendedUsers.hwids.set(s.value, s); else if (s.type === 'userId') suspendedUsers.userIds.set(s.value, s); else if (s.type === 'session') suspendedUsers.sessions.set(s.value, s); }); }
}

async function logAccess(r, a, s, d = {}) {
const log = { ip: getIP(r), hwid: getHWID(r), ua: (r.headers['user-agent'] || '').substring(0, 100), action: a, success: s, client: getClientType(r), ts: new Date().toISOString(), ...d };
await db.addLog(log); return log;
}

function genChallenge() {
const types = ['math', 'bitwise', 'sequence', 'sum'];
const type = types[Math.floor(Math.random() * types.length)];
switch (type) {
case 'math': const op = ['+', '-', '*'][Math.floor(Math.random() * 3)], a = Math.floor(Math.random() * 50) + 10, b = Math.floor(Math.random() * 20) + 5, c = Math.floor(Math.random() * 10) + 1; let ans; if (op === '+') ans = (a + b) * c; else if (op === '-') ans = (a - b) * c; else ans = (a * b) + c; return { type: 'math', puzzle: { a, b, c, op }, answer: ans };
case 'bitwise': const x = Math.floor(Math.random() * 200) + 50, y = Math.floor(Math.random() * 100) + 20, bop = ['xor', 'and', 'or'][Math.floor(Math.random() * 3)]; let bans; if (bop === 'xor') bans = x ^ y; else if (bop === 'and') bans = x & y; else bans = x | y; return { type: 'bitwise', puzzle: { x, y, op: bop }, answer: bans };
case 'sequence': const start = Math.floor(Math.random() * 15) + 1, step = Math.floor(Math.random() * 8) + 2; return { type: 'sequence', puzzle: { seq: [start, start + step, start + step * 2, start + step * 3] }, answer: start + step * 4 };
default: const nums = Array.from({ length: 5 }, () => Math.floor(Math.random() * 50) + 1); return { type: 'sum', puzzle: { numbers: nums }, answer: nums.reduce((a, b) => a + b, 0) };
}
}

async function getScript() {
const cached = await db.getCachedScript();
if (cached) return cached;
let script = null;
const encKey = config.SCRIPT_ENCRYPTION_KEY || config.SECRET_KEY;
if (encKey) {
script = await db.getXorScript(encKey);
if (script) console.log('[Script] Loaded from Redis (XOR encrypted)');
}
if (!script && config.SCRIPT_SOURCE_URL) {
console.log('[Script] Fallback to URL...');
try { const res = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 15000 }); script = res.data; console.log('[Script] Loaded from URL'); } catch (e) { console.error('[Script] Fetch error:', e.message); }
}
if (script) await db.setCachedScript(script, 300);
return script;
}

function isObfuscated(s) { if (!s) return false; return [/Luraph/i, /Moonsec/i, /IronBrew/i, /Prometheus/i, /PSU/i].some(r => r.test(s.substring(0, 500))); }

function wrapScript(s, serverUrl) {
const o = (config.OWNER_USER_IDS || []).map(id => `[${id}]=true`).join(',');
const w = (config.WHITELIST_USER_IDS || []).map(id => `[${id}]=true`).join(',');
const sid = crypto.randomBytes(16).toString('hex');
const antiSpyEnabled = config.ANTI_SPY_ENABLED !== false;
return `--[[Shield v2.3]]local _CFG={o={${o}},w={${w}},wh="${serverUrl}/api/webhook/suspicious",hb="${serverUrl}/api/heartbeat",sid="${sid}",as=${antiSpyEnabled},hbi=45} local PS=game:GetService("Players") local CG=game:GetService("CoreGui") local SG=game:GetService("StarterGui") local HS=game:GetService("HttpService") local LP=PS.LocalPlayer local _A=true local _C={} local _HF=0 local _SS={} local _DC={}
local function NT(t,x,d) pcall(function() SG:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local function GH() local s,r=pcall(function() if gethwid then return gethwid() end if getexecutorname then return getexecutorname()..tostring(LP.UserId) end return "NK_"..tostring(LP.UserId) end) return s and r or "UNK" end
local function HP(u,d) local rq=(syn and syn.request)or request or http_request or(http and http.request) if not rq then return end pcall(function() rq({Url=u,Method="POST",Headers={["Content-Type"]="application/json",["User-Agent"]="Roblox/WinInet",["x-hwid"]=GH(),["x-roblox-id"]=tostring(LP.UserId),["x-session-id"]=_CFG.sid},Body=HS:JSONEncode(d)}) end) end
local function IW(u) return _CFG.w[u]==true end
local function IO(u) return _CFG.o[u]==true end
local function TM(r,tn) if not _A then return end _A=false HP(_CFG.wh,{userId=LP.UserId,tool=tn or r,reason=r,sessionId=_CFG.sid,hwid=GH()}) NT("Security",r or "Terminated",3) for i=#_C,1,-1 do pcall(function() _C[i]:Disconnect() end) end task.wait(0.5) pcall(function() if LP.Character then LP.Character:BreakJoints() end end) task.wait(0.5) pcall(function() LP:Kick(r or "Security Violation") end) end
local function IsToolGui(gui) if not gui then return false,nil end local dominated=false pcall(function() if not gui:IsA("ScreenGui") and not gui:IsA("Frame") then return end if gui:IsA("ScreenGui") and gui.Enabled==false then return end local n=gui.Name:lower() local dominated_names={"simplespy","remotespy","httpspy","synspy","infiniteyield","infinite_yield","iy_main","dex","dexexplorer","darkdex","hydroxide"} for _,dn in ipairs(dominated_names) do if n:find(dn) then dominated=true return end end local child_count=0 pcall(function() child_count=#gui:GetDescendants() end) if child_count<3 then return end local has_textbox,has_scrollframe=false,false pcall(function() for _,v in pairs(gui:GetDescendants()) do if v:IsA("TextBox") then has_textbox=true end if v:IsA("ScrollingFrame") then has_scrollframe=true end end end) if n:find("spy") or n:find("remote") or n:find("logger") then if has_textbox or has_scrollframe then dominated=true end end if n:find("dex") or n:find("explorer") then if has_scrollframe then dominated=true end end if n:find("iy") or n:find("infinite") or n:find("yield") then if has_textbox then dominated=true end end end) return dominated,gui.Name end
local function ScanForActiveTools() if not _CFG.as or IW(LP.UserId) then return false,nil end local found,toolname=false,nil pcall(function() for _,gui in pairs(CG:GetChildren()) do if gui:IsA("ScreenGui") and gui.Enabled==true then local ss_name=gui.Name:lower() if _SS[ss_name] or _DC[ss_name] then continue end local is_tool,name=IsToolGui(gui) if is_tool then found,toolname=true,name _DC[ss_name]=true return end end end end) return found,toolname end
local function TakeSnapshot() pcall(function() for _,gui in pairs(CG:GetChildren()) do if gui:IsA("ScreenGui") then _SS[gui.Name:lower()]=true end end end) end
local function StartMonitor() table.insert(_C,CG.ChildAdded:Connect(function(child) if not _A or not child:IsA("ScreenGui") then return end task.wait(0.5) if not _A then return end local ss_name=child.Name:lower() if _SS[ss_name] or _DC[ss_name] then return end pcall(function() if child.Enabled==true then local is_tool,name=IsToolGui(child) if is_tool then _DC[ss_name]=true TM("Spy Tool: "..name,name) end end end) end)) task.spawn(function() task.wait(5) while _A do local found,toolname=ScanForActiveTools() if found then TM("Spy Tool: "..toolname,toolname) break end task.wait(5) end end) end
local function COP() for _,p in pairs(PS:GetPlayers()) do if IO(p.UserId) and p~=LP then return false end end return true end
local function SOM() table.insert(_C,PS.PlayerAdded:Connect(function(p) task.wait(1) if IO(p.UserId) and _A then TM("Owner joined","OwnerProtection") end end)) end
local function SHB() task.spawn(function() task.wait(15) while _A do local res local rq=(syn and syn.request)or request or http_request or(http and http.request) if rq then local s,r=pcall(function() return rq({Url=_CFG.hb,Method="POST",Headers={["Content-Type"]="application/json",["x-session-id"]=_CFG.sid},Body=HS:JSONEncode({sessionId=_CFG.sid,hwid=GH(),userId=LP.UserId})}) end) if s and r and r.StatusCode==200 then local ok,bd=pcall(function() return HS:JSONDecode(r.Body) end) if ok then res=bd end end end if res then _HF=0 if res.action=="TERMINATE" then TM(res.reason or "Terminated","Heartbeat") break elseif res.action=="MESSAGE" and res.message then NT("Message",res.message,5) end else _HF=_HF+1 if _HF>=5 then TM("Connection lost","Heartbeat") break end end task.wait(_CFG.hbi) end end) end
if not COP() then NT("Warning","Owner in server!",5) return end TakeSnapshot() SOM() StartMonitor() SHB() NT("Shield","Protection active",3)
${s}`;
}

function getLoader(url) {
return `local S="${url}" local H=game:GetService("HttpService") local P=game:GetService("Players") local L=P.LocalPlayer local function n(t,x,d)pcall(function()game:GetService("StarterGui"):SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3})end)end local function hp(u,d)local r=(syn and syn.request)or request or http_request or(http and http.request)if not r then return nil end;local s,res=pcall(function()return r({Url=u,Method="POST",Headers={["Content-Type"]="application/json",["User-Agent"]="Roblox/WinInet",["x-hwid"]=(gethwid and gethwid() or "UNK"),["x-roblox-id"]=tostring(L.UserId),["x-place-id"]=tostring(game.PlaceId)},Body=H:JSONEncode(d)})end) if s and res and res.StatusCode==200 then local ok,body=pcall(function()return H:JSONDecode(res.Body)end) if ok then return body end end return nil end local function xd(data,key)local r={} for i=1,#data do local b=data[i] local k=string.byte(key,((i-1)%#key)+1) table.insert(r,string.char(bit32.bxor(b,k))) end return table.concat(r) end local function sv(p)if not p or not p.type then return 0 end;if p.type=="math"then local a,b,c,op=p.puzzle.a,p.puzzle.b,p.puzzle.c,p.puzzle.op;if op=="+"then return(a+b)*c elseif op=="-"then return(a-b)*c else return(a*b)+c end elseif p.type=="bitwise"then local x,y,op=p.puzzle.x,p.puzzle.y,p.puzzle.op;if op=="xor"then return bit32.bxor(x,y)elseif op=="and"then return bit32.band(x,y)else return bit32.bor(x,y)end elseif p.type=="sequence"then local s=p.puzzle.seq;return s[4]+(s[2]-s[1])elseif p.puzzle and p.puzzle.numbers then local sum=0;for _,x in ipairs(p.puzzle.numbers)do sum=sum+x end;return sum end;return 0 end local function asm(v)if not v then return nil end;if v.mode=="raw"then return v.script end;if v.mode=="chunked"then local p={} for _,c in ipairs(v.chunks)do local k=v.keys[c.index+1] if k and c.data then p[c.index+1]=xd(c.data,k) end end return table.concat(p) end return nil end n("Loading","Connecting...",2) local c=hp(S.."/api/auth/challenge",{userId=L.UserId,hwid=(gethwid and gethwid() or "UNK"),placeId=game.PlaceId}) if c and c.success then n("Loading","Verifying...",2) local v=hp(S.."/api/auth/verify",{challengeId=c.challengeId,solution=sv(c),timestamp=os.time()}) if v and v.success then n("Loading","Loading...",2) local fs=asm(v) if fs then local f,e=loadstring(fs) if f then pcall(f) n("Success","Loaded!",2) else n("Error","Syntax: "..(e or "?"),5) end else n("Error","Assembly Failed",5) end else n("Error","Verify Failed",5) end else n("Error","Connection Failed",5) end`;
}

function getEncodedLoader(url, req) {
const key = genLoaderKey(req); const enc = encryptLoader(getLoader(url), key);
return `local k="${key}"local d="${enc}"local function x(s,k)local r={}local b={}for i=1,#s do b[i]=s:byte(i)end;for i=1,#b do r[i]=string.char(bit32.bxor(b[i],k:byte((i-1)%#k+1)))end;return table.concat(r)end;local function b(s)local t={}local c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"for i=1,64 do t[c:sub(i,i)]=i-1 end;s=s:gsub("[^"..c.."=]","")local r={}local n=1;for i=1,#s,4 do local a,b,c,d=t[s:sub(i,i)]or 0,t[s:sub(i+1,i+1)]or 0,t[s:sub(i+2,i+2)]or 0,t[s:sub(i+3,i+3)]or 0;local v=a*262144+b*4096+c*64+d;r[n]=string.char(bit32.rshift(v,16)%256)n=n+1;if s:sub(i+2,i+2)~="="then r[n]=string.char(bit32.rshift(v,8)%256)n=n+1 end;if s:sub(i+3,i+3)~="="then r[n]=string.char(v%256)n=n+1 end end;return table.concat(r)end;loadstring(x(b(d),k))()`;
}

const viewsPath = path.join(__dirname, 'views');
const LOADER_HTML = fs.existsSync(path.join(viewsPath, 'loader/index.html')) ? fs.readFileSync(path.join(viewsPath, 'loader/index.html'), 'utf8') : `<h1>Loader</h1>`;
const TRAP_HTML = fs.existsSync(path.join(viewsPath, 'trap/index.html')) ? fs.readFileSync(path.join(viewsPath, 'trap/index.html'), 'utf8') : `<!DOCTYPE html><html><head><title>403</title></head><body style="background:#0a0a0f;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif"><div style="text-align:center"><h1 style="font-size:60px">🛡️</h1><h2 style="color:#ef4444">Access Denied</h2></div></body></html>`;

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'x-admin-key', 'x-hwid', 'x-roblox-id', 'x-place-id', 'x-job-id', 'x-session-id'] }));
app.use(express.json({ limit: '10mb' }));
app.set('trust proxy', 1);
app.use(rateLimit({ windowMs: 60000, max: 100, keyGenerator: r => getIP(r) }));
app.use('/admin/css', express.static(path.join(viewsPath, 'admin/css')));
app.use('/admin/js', express.static(path.join(viewsPath, 'admin/js')));

app.use(async (req, res, next) => {
const ap = config.ADMIN_PATH || '/admin';
if (req.path.startsWith(ap) || req.path === '/health' || req.path === '/loader' || req.path === '/l' || req.path.startsWith('/api/admin')) return next();
const ban = await db.isBanned(null, getIP(req), null);
if (ban.blocked) { if (getClientType(req) === 'browser') return res.status(403).type('html').send(TRAP_HTML); return res.status(403).type('text/plain').send(genFakeScript()); }
next();
});

const adminAuth = (req, res, next) => {
const k = req.headers['x-admin-key'] || req.query.key;
if (!k) return res.status(403).json({ success: false, error: 'Unauthorized' });
if (!config.ADMIN_KEY) return res.status(500).json({ success: false, error: 'Server misconfigured' });
if (!secureCompare(k, config.ADMIN_KEY)) return res.status(403).json({ success: false, error: 'Unauthorized' });
next();
};

const adminPath = config.ADMIN_PATH || '/admin';
app.get(adminPath, (req, res) => { const f = path.join(viewsPath, 'admin/index.html'); if (fs.existsSync(f)) res.sendFile(f); else res.status(404).send('Not found'); });
app.get('/health', (req, res) => res.json({ status: 'ok', redis: db.isRedisConnected?.() ?? false }));

// ═══════════════════════════════════════════════════════════════════
// UPLOAD SCRIPT ENDPOINT - Fetch dari URL, Encrypt, Simpan ke Redis
// ═══════════════════════════════════════════════════════════════════
app.get('/api/admin/upload-script', adminAuth, (req, res) => {
res.send(`<!DOCTYPE html><html><head><title>Upload Script</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family:Arial;padding:20px;background:#1a1a2e;color:#fff;max-width:600px;margin:0 auto}input,button{width:100%;padding:15px;margin:10px 0;font-size:16px;box-sizing:border-box;border-radius:8px;border:1px solid #333}input{background:#0d0d1a;color:#fff}button{background:#4CAF50;color:white;border:none;cursor:pointer;font-weight:bold}button:hover{background:#45a049}.info{background:#0d0d1a;padding:15px;margin:15px 0;border-radius:8px;border:1px solid #333}.success{border-color:#4CAF50;color:#4CAF50}.error{border-color:#f44336;color:#f44336}h2{color:#4CAF50;text-align:center}label{color:#888;font-size:14px}</style></head><body><h2>🔐 Upload Script ke Redis</h2><div class="info"><p>✅ Script akan di-fetch dari URL</p><p>✅ Di-encrypt dengan XOR</p><p>✅ Disimpan ke Redis</p><p>✅ URL tidak terekspos ke client!</p></div><label>Script URL (GitHub Raw / Pastebin Raw):</label><input type="text" id="url" placeholder="https://raw.githubusercontent.com/user/repo/main/script.lua"><label>Encryption Key (min 16 karakter):</label><input type="text" id="key" placeholder="MySecretKey123456789"><button onclick="upload()">🚀 UPLOAD & ENCRYPT</button><div id="result"></div><script>async function upload(){const url=document.getElementById('url').value;const key=document.getElementById('key').value;const resultDiv=document.getElementById('result');if(!url){alert('URL required!');return}if(!key||key.length<16){alert('Key minimal 16 karakter!');return}resultDiv.innerHTML='<div class="info">⏳ Uploading...</div>';try{const res=await fetch('/api/admin/upload-script',{method:'POST',headers:{'Content-Type':'application/json','x-admin-key':new URLSearchParams(window.location.search).get('key')},body:JSON.stringify({url,encryptionKey:key})});const data=await res.json();if(data.success){resultDiv.innerHTML='<div class="info success"><h3>✅ Berhasil!</h3><p>📦 Size: '+data.size+' bytes</p><p>🔑 Hash: '+data.hash+'</p><p>📅 Updated: '+data.updatedAt+'</p><hr><p><strong>⚠️ PENTING:</strong></p><p>Tambahkan ini di Render Environment:</p><p><code>SCRIPT_ENCRYPTION_KEY='+key+'</code></p></div>'}else{resultDiv.innerHTML='<div class="info error"><h3>❌ Error</h3><p>'+data.error+'</p></div>'}}catch(e){resultDiv.innerHTML='<div class="info error"><h3>❌ Error</h3><p>'+e.message+'</p></div>'}}</script></body></html>`);
});

app.post('/api/admin/upload-script', adminAuth, async (req, res) => {
const { url, encryptionKey } = req.body;
if (!url) return res.status(400).json({ success: false, error: 'URL required' });
if (!encryptionKey || encryptionKey.length < 16) return res.status(400).json({ success: false, error: 'Encryption key min 16 chars' });
try {
console.log('[Upload] Fetching:', url);
const response = await axios.get(url, { timeout: 30000, maxContentLength: 10 * 1024 * 1024 });
const script = response.data;
if (!script || script.length < 10) return res.status(400).json({ success: false, error: 'Script empty' });
console.log('[Upload] Size:', script.length);
const success = await db.setXorScript(script, encryptionKey);
if (!success) return res.status(500).json({ success: false, error: 'Failed to save to Redis' });
const redis = await db.getRedisClient();
if (redis) {
await redis.set('script:hash', crypto.createHash('md5').update(script).digest('hex').substring(0, 8));
await redis.set('script:updated', new Date().toISOString());
await redis.set('script:size', script.length.toString());
}
console.log('[Upload] ✅ Success!');
res.json({ success: true, message: 'Uploaded!', size: script.length, hash: crypto.createHash('md5').update(script).digest('hex').substring(0, 8), updatedAt: new Date().toISOString() });
} catch (e) {
console.error('[Upload] Error:', e.message);
res.status(500).json({ success: false, error: e.message });
}
});

app.get('/api/admin/script-info', adminAuth, async (req, res) => {
const info = await db.getScriptInfo();
res.json({ success: true, info });
});
// ═══════════════════════════════════════════════════════════════════

app.get(['/loader', '/api/loader.lua', '/api/loader', '/l'], async (req, res) => {
const ct = getClientType(req), ip = getIP(req), hwid = getHWID(req), userId = req.headers['x-roblox-id'] || null;
const ban = await db.isBanned(hwid, ip, userId);
if (ban.blocked) { await logAccess(req, 'LOADER_BANNED', false, { clientType: ct, ip, hwid, userId, banReason: ban.reason }); if (ct === 'browser') return res.status(403).type('html').send(TRAP_HTML); return res.status(403).json({ success: false, error: 'Banned' }); }
if (ct === 'browser') return res.status(200).type('html').send(LOADER_HTML);
if (shouldBlock(req)) { await logAccess(req, 'LOADER_BOT_FAKE', false, { clientType: ct, ip }); return res.status(200).type('text/plain').send(genFakeScript()); }
await logAccess(req, 'LOADER', true, { clientType: ct, userId });
const isWL = await checkWhitelist(hwid, userId, req);
const url = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
if (config.ENCODE_LOADER !== false && !isWL) res.type('text/plain').send(getEncodedLoader(url, req)); else res.type('text/plain').send(getLoader(url));
});

app.post('/api/auth/challenge', async (req, res) => {
const ct = getClientType(req);
if (shouldBlock(req)) { await logAccess(req, 'CHALLENGE_BLOCKED', false, { clientType: ct }); return res.status(403).json({ success: false, error: 'Access denied' }); }
const { userId, hwid, placeId } = req.body;
if (!userId || !placeId) return res.status(400).json({ success: false, error: 'Missing fields' });
const uid = parseInt(userId), pid = parseInt(placeId);
if (isNaN(uid) || isNaN(pid)) return res.status(400).json({ success: false, error: 'Invalid format' });
const ip = getIP(req);
const isWL = await checkWhitelist(hwid, uid, req);
const susp = checkSuspended(hwid, uid, null);
if (susp) return res.json({ success: false, error: 'Suspended: ' + susp.reason });
if (!isWL) { const ban = await db.isBanned(hwid, ip, uid); if (ban.blocked) return res.json({ success: false, error: 'Banned: ' + ban.reason }); }
if (config.ALLOWED_PLACE_IDS?.length > 0 && !config.ALLOWED_PLACE_IDS.includes(pid) && !isWL) return res.status(403).json({ success: false, error: 'Game not authorized' });
await logAccess(req, 'CHALLENGE', true, { clientType: ct, whitelisted: isWL, userId: uid });
const id = crypto.randomBytes(16).toString('hex');
const chal = genChallenge();
await db.setChallenge(id, { id, userId: uid, hwid: hwid || 'none', placeId: pid, ip, whitelisted: isWL, ...chal }, 120);
res.json({ success: true, challengeId: id, type: chal.type, puzzle: chal.puzzle, expiresIn: 120 });
});

app.post('/api/auth/verify', async (req, res) => {
const ct = getClientType(req);
if (shouldBlock(req)) return res.status(403).json({ success: false, error: 'Access denied' });
const { challengeId, solution, timestamp } = req.body;
if (!challengeId || solution === undefined || !timestamp) return res.status(400).json({ success: false, error: 'Missing fields' });
const challenge = await db.getChallenge(challengeId);
if (!challenge) return res.status(403).json({ success: false, error: 'Challenge expired' });
if (challenge.ip !== getIP(req)) return res.status(403).json({ success: false, error: 'IP mismatch' });
if (parseInt(solution) !== challenge.answer) return res.status(403).json({ success: false, error: 'Wrong solution' });
await db.deleteChallenge(challengeId);
const script = await getScript();
if (!script) return res.status(500).json({ success: false, error: 'Script not available' });
const url = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
const wrapped = wrapScript(script, url);
const sessionId = crypto.randomBytes(16).toString('hex');
SESSIONS.set(sessionId, { hwid: challenge.hwid, ip: challenge.ip, userId: challenge.userId, placeId: challenge.placeId, created: Date.now(), lastSeen: Date.now() });
webhook.execution?.({ userId: challenge.userId, hwid: challenge.hwid, placeId: challenge.placeId, ip: challenge.ip, executor: req.headers['user-agent'] }).catch(() => {});
await logAccess(req, 'VERIFY_SUCCESS', true, { userId: challenge.userId });
if (config.CHUNK_DELIVERY !== false || challenge.whitelisted) { const ckd = await prepareChunks(wrapped, challenge); return res.json({ success: true, mode: 'chunked', chunks: ckd.chunks, keys: ckd.keys, sessionId }); }
res.json({ success: true, mode: 'raw', script: wrapped, sessionId });
});

app.post('/api/heartbeat', async (req, res) => {
const { sessionId, hwid, userId } = req.body;
if (!sessionId) return res.json({ success: true, action: 'CONTINUE' });
const session = SESSIONS.get(sessionId);
if (session) session.lastSeen = Date.now();
const sp = checkSuspended(hwid, userId, sessionId);
if (sp) return res.json({ success: false, action: 'TERMINATE', reason: sp.reason });
const ban = await db.isBanned(hwid, getIP(req), userId);
if (ban.blocked) return res.json({ success: false, action: 'TERMINATE', reason: 'Banned: ' + ban.reason });
res.json({ success: true, action: 'CONTINUE' });
});

app.post('/api/webhook/suspicious', async (req, res) => {
const { userId, hwid, tool, sessionId, reason } = req.body;
await logAccess(req, 'SUSPICIOUS', false, { userId, hwid, tool, reason });
webhook.suspicious?.({ userId, hwid, ip: getIP(req), reason: reason || 'Spy tool: ' + tool, tool, action: 'Kicked' }).catch(() => {});
res.json({ success: true });
});

app.post('/api/ban', async (req, res) => {
const { hwid, playerId, reason, sessionId } = req.body;
if (!hwid && !playerId) return res.status(400).json({ error: 'Missing id' });
const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
const banData = { ip: getIP(req), reason: reason || 'Auto', banId, ts: new Date().toISOString() };
if (hwid) await db.addBan(hwid, { hwid, ...banData });
if (playerId) await db.addBan(String(playerId), { playerId, ...banData });
if (sessionId) SESSIONS.delete(sessionId);
await logAccess(req, 'BAN_ADDED', true, { hwid, playerId, reason });
webhook.ban?.({ userId: playerId, hwid, ip: getIP(req), reason, bannedBy: 'System', banId }).catch(() => {});
res.json({ success: true, banId });
});

app.get('/api/admin/stats', adminAuth, async (req, res) => { const s = await db.getStats(); res.json({ success: true, stats: s, sessions: SESSIONS.size, ts: new Date().toISOString() }); });
app.get('/api/admin/logs', adminAuth, async (req, res) => { const l = await db.getLogs(50); res.json({ success: true, logs: l }); });
app.post('/api/admin/logs/clear', adminAuth, async (req, res) => { await db.clearLogs(); res.json({ success: true }); });
app.get('/api/admin/bans', adminAuth, async (req, res) => { const b = await db.getAllBans(); res.json({ success: true, bans: b }); });
app.post('/api/admin/bans', adminAuth, async (req, res) => { const { hwid, ip, playerId, reason } = req.body; if (!hwid && !ip && !playerId) return res.status(400).json({ success: false, error: 'Required' }); const banId = crypto.randomBytes(8).toString('hex').toUpperCase(); const data = { reason: reason || 'Manual', banId, ts: new Date().toISOString() }; if (hwid) await db.addBan(hwid, { hwid, ...data }); if (playerId) await db.addBan(String(playerId), { playerId, ...data }); if (ip) await db.addBan(ip, { ip, ...data }); res.json({ success: true, banId }); });
app.delete('/api/admin/bans/:id', adminAuth, async (req, res) => { const r = await db.removeBanById(req.params.id); res.json({ success: r }); });
app.post('/api/admin/bans/clear', adminAuth, async (req, res) => { const count = await db.clearBans(); res.json({ success: true, cleared: count }); });
app.post('/api/admin/cache/clear', adminAuth, async (req, res) => { await db.setCachedScript(null); res.json({ success: true }); });
app.post('/api/admin/sessions/clear', adminAuth, async (req, res) => { const count = SESSIONS.size; SESSIONS.clear(); res.json({ success: true, cleared: count }); });
app.get('/api/admin/whitelist', adminAuth, (req, res) => { res.json({ success: true, whitelist: { userIds: [...(config.WHITELIST_USER_IDS || []), ...Array.from(dynamicWhitelist.userIds)], hwids: [...(config.WHITELIST_HWIDS || []), ...Array.from(dynamicWhitelist.hwids)], ips: [...(config.WHITELIST_IPS || []), ...Array.from(dynamicWhitelist.ips)], owners: config.OWNER_USER_IDS || [] } }); });
app.post('/api/admin/whitelist', adminAuth, (req, res) => { const { type, value } = req.body; if (!type || !value) return res.status(400).json({ success: false, error: 'Missing' }); if (type === 'userId') dynamicWhitelist.userIds.add(parseInt(value)); else if (type === 'hwid') dynamicWhitelist.hwids.add(String(value)); else if (type === 'ip') dynamicWhitelist.ips.add(String(value)); res.json({ success: true }); });
app.post('/api/admin/whitelist/remove', adminAuth, (req, res) => { const { type, value } = req.body; if (type === 'userId') dynamicWhitelist.userIds.delete(parseInt(value)); else if (type === 'hwid') dynamicWhitelist.hwids.delete(String(value)); else if (type === 'ip') dynamicWhitelist.ips.delete(String(value)); res.json({ success: true }); });
app.get('/api/admin/suspended', adminAuth, async (req, res) => { const a = []; suspendedUsers.hwids.forEach((v, k) => a.push({ type: 'hwid', value: k, ...v })); suspendedUsers.userIds.forEach((v, k) => a.push({ type: 'userId', value: k, ...v })); suspendedUsers.sessions.forEach((v, k) => a.push({ type: 'session', value: k, ...v })); res.json({ success: true, suspended: a }); });
app.post('/api/admin/suspend', adminAuth, async (req, res) => { const { type, value, reason, duration } = req.body; if (!type || !value) return res.status(400).json({ success: false, error: 'Missing' }); const d = { reason: reason || 'Suspended', suspendedAt: new Date().toISOString(), expiresAt: duration ? new Date(Date.now() + parseInt(duration) * 1000).toISOString() : null }; if (type === 'hwid') suspendedUsers.hwids.set(String(value), d); else if (type === 'userId') suspendedUsers.userIds.set(String(value), d); else if (type === 'session') suspendedUsers.sessions.set(String(value), d); await db.addSuspend(type, String(value), d); res.json({ success: true }); });
app.post('/api/admin/unsuspend', adminAuth, async (req, res) => { const { type, value } = req.body; if (type === 'hwid') suspendedUsers.hwids.delete(String(value)); else if (type === 'userId') suspendedUsers.userIds.delete(String(value)); else if (type === 'session') suspendedUsers.sessions.delete(String(value)); await db.removeSuspend(type, String(value)); res.json({ success: true }); });
app.post('/api/admin/kill-session', adminAuth, async (req, res) => { const { sessionId, reason } = req.body; if (!sessionId) return res.status(400).json({ success: false, error: 'Missing' }); const session = SESSIONS.get(sessionId); if (!session) return res.status(404).json({ success: false, error: 'Not found' }); await suspendUser('session', sessionId, { reason: reason || 'Killed', userId: session.userId, hwid: session.hwid, ip: session.ip }); res.json({ success: true }); });
app.get('/api/admin/sessions', adminAuth, (req, res) => { const arr = []; SESSIONS.forEach((v, k) => arr.push({ sessionId: k, ...v, age: Math.floor((Date.now() - v.created) / 1000) })); res.json({ success: true, sessions: arr.sort((a, b) => b.created - a.created) }); });

app.use('*', (req, res) => { const ct = getClientType(req); if (ct === 'browser') return res.status(404).type('html').send(TRAP_HTML); res.status(403).type('text/plain').send(genFakeScript()); });

const PORT = process.env.PORT || config.PORT || 3000;
loadSuspendedFromDB().then(() => { webhook.serverStart?.().catch(() => {}); app.listen(PORT, '0.0.0.0', () => { console.log(`\n🛡️ Shield v2.3 running on port ${PORT}\n📍 Admin: http://localhost:${PORT}${adminPath}\n📦 Loader: http://localhost:${PORT}/loader\n📤 Upload: http://localhost:${PORT}/api/admin/upload-script?key=ADMIN_KEY\n`); }); });
