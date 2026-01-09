/* ============================================
   SCRIPT SHIELD - Main Server
   Luarmor-style protection system
   ============================================ */

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

const app = express();
const SESSIONS = new Map();

// ==================== CONSTANTS ====================
const ALLOWED_EXECUTORS = [
    'delta', 'fluxus', 'krnl', 'oxygen', 'evon', 'hydrogen', 
    'vegax', 'trigon', 'comet', 'solara', 'wave', 'zorara', 
    'codex', 'celery', 'swift', 'sirhurt', 'electron', 'sentinel', 
    'coco', 'temple', 'valyse', 'nihon', 'jjsploit', 'wearedevs'
];

const BLOCKED_EXECUTORS = ['synapse', 'arceus', 'script-ware', 'scriptware'];

const BOT_UA = [
    'python', 'curl', 'wget', 'axios', 'node-fetch', 'aiohttp', 
    'httpx', 'requests/', 'postman', 'insomnia', 'discord.', 
    'telegram', 'scrapy', 'selenium', 'puppeteer', 'java/', 
    'okhttp', 'perl', 'php/', 'ruby', 'go-http', 'got/', 
    'undici', 'urllib', 'apache', 'libwww', 'bot', 'crawler', 
    'spider', 'fiddler', 'charles', 'mitmproxy', 'burp'
];

// ==================== UTILITY FUNCTIONS ====================
function sha256(s) {
    return crypto.createHash('sha256').update(s).digest('hex');
}

function hmac(d, k) {
    return crypto.createHmac('sha256', k).update(d).digest('hex');
}

function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
        return false;
    }
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

function getIP(r) {
    return (r.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
        r.headers['x-real-ip'] ||
        r.ip ||
        '0.0.0.0';
}

function getHWID(r) {
    return r.headers['x-hwid'] || null;
}

function genSessionKey(u, h, t, s) {
    return hmac(`${u}:${h}:${t}`, s).substring(0, 32);
}

// ==================== FAKE SCRIPT GENERATOR ====================
function genFakeScript() {
    const randStr = (len) => {
        let s = '';
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        for (let i = 0; i < len; i++) {
            s += chars[Math.floor(Math.random() * chars.length)];
        }
        return s;
    };
    
    const vars = [];
    for (let i = 0; i < 20; i++) {
        vars.push(randStr(Math.floor(Math.random() * 8) + 4));
    }
    
    return `--[[ Luraph v14.4.7 | Protected Script ]]
local ${vars[0]},${vars[1]},${vars[2]}
local ${vars[3]}=(function()
local ${vars[4]}={${Array(50).fill(0).map(() => `"${randStr(10)}"`).join(',')}}
return ${vars[4]} end)()
local ${vars[5]}=coroutine.wrap(function()
for ${vars[6]}=1,${Math.floor(Math.random() * 50000) + 10000} do
coroutine.yield(bit32.bxor(${vars[6]},${Math.floor(Math.random() * 99999)}))
end end)
--[[ Anti-Tamper Enabled ]]`;
}

// ==================== CLIENT DETECTION ====================
function getClientType(r) {
    const ua = (r.headers['user-agent'] || '').toLowerCase();
    const hasHWID = !!r.headers['x-hwid'];
    const hasRobloxId = !!r.headers['x-roblox-id'];
    const hasPlaceId = !!r.headers['x-place-id'];
    const hasJobId = !!r.headers['x-job-id'];
    const hasExecutorHeaders = hasHWID || hasRobloxId || hasPlaceId || hasJobId;
    
    if (BLOCKED_EXECUTORS.some(e => ua.includes(e))) return 'blocked_executor';
    if (hasExecutorHeaders) return 'executor';
    if (ALLOWED_EXECUTORS.some(e => ua.includes(e))) return 'executor';
    if (ua.includes('roblox') || ua.includes('wininet')) return 'executor';
    
    if (r.headers['sec-fetch-dest'] || r.headers['sec-fetch-mode'] || 
        r.headers['sec-ch-ua'] || r.headers['upgrade-insecure-requests']) {
        return 'browser';
    }
    
    const accept = r.headers['accept'] || '';
    if (accept.includes('text/html') && r.headers['accept-language']) return 'browser';
    
    if (!ua || ua.length < 5 || ua === 'mozilla/5.0') return 'bot';
    if (BOT_UA.some(p => ua.includes(p))) return 'bot';
    if (!hasExecutorHeaders) return 'unknown';
    
    return 'executor';
}

// ==================== LOGGING ====================
async function logAccess(r, a, s, d = {}) {
    const log = {
        ip: getIP(r),
        hwid: getHWID(r),
        ua: (r.headers['user-agent'] || '').substring(0, 100),
        action: a,
        success: s,
        path: r.path,
        client: getClientType(r),
        ts: new Date().toISOString(),
        ...d
    };
    await db.addLog(log);
    return log;
}

// ==================== CHALLENGE GENERATOR ====================
function genChallenge() {
    const types = ['math', 'bitwise', 'sequence', 'sum'];
    const type = types[Math.floor(Math.random() * types.length)];
    
    switch (type) {
        case 'math': {
            const op = ['+', '-', '*'][Math.floor(Math.random() * 3)];
            const a = Math.floor(Math.random() * 50) + 10;
            const b = Math.floor(Math.random() * 20) + 5;
            const c = Math.floor(Math.random() * 10) + 1;
            let ans;
            if (op === '+') ans = (a + b) * c;
            else if (op === '-') ans = (a - b) * c;
            else ans = (a * b) + c;
            return { type: 'math', puzzle: { a, b, c, op }, answer: ans };
        }
        case 'bitwise': {
            const x = Math.floor(Math.random() * 200) + 50;
            const y = Math.floor(Math.random() * 100) + 20;
            const bop = ['xor', 'and', 'or'][Math.floor(Math.random() * 3)];
            let bans;
            if (bop === 'xor') bans = x ^ y;
            else if (bop === 'and') bans = x & y;
            else bans = x | y;
            return { type: 'bitwise', puzzle: { x, y, op: bop }, answer: bans };
        }
        case 'sequence': {
            const start = Math.floor(Math.random() * 15) + 1;
            const step = Math.floor(Math.random() * 8) + 2;
            return {
                type: 'sequence',
                puzzle: { seq: [start, start + step, start + step * 2, start + step * 3] },
                answer: start + step * 4
            };
        }
        default: {
            const nums = Array.from({ length: 5 }, () => Math.floor(Math.random() * 50) + 1);
            return {
                type: 'sum',
                puzzle: { numbers: nums },
                answer: nums.reduce((a, b) => a + b, 0)
            };
        }
    }
}

// ==================== SCRIPT HANDLING ====================
function isObfuscated(s) {
    if (!s) return false;
    const patterns = [/Luraph/i, /Moonsec/i, /IronBrew/i, /Prometheus/i, /PSU/i];
    return patterns.some(r => r.test(s.substring(0, 500)));
}

async function getScript() {
    const cached = await db.getCachedScript();
    if (cached) return cached;
    
    if (!config.SCRIPT_SOURCE_URL) return null;
    
    try {
        const res = await axios.get(config.SCRIPT_SOURCE_URL, {
            timeout: 30000,
            headers: { 'User-Agent': 'Roblox/WinInet' },
            maxContentLength: 50000000
        });
        
        if (typeof res.data === 'string' && res.data.length > 50) {
            await db.setCachedScript(res.data);
            return res.data;
        }
    } catch (e) {
        console.error('Failed to fetch script:', e.message);
    }
    
    return null;
}

// ==================== SCRIPT WRAPPER ====================
function wrapScript(script, serverUrl) {
    const ownerIds = config.OWNER_USER_IDS.join(',');
    const whitelistIds = config.WHITELIST_USER_IDS.join(',');
    const banUrl = `${serverUrl}/api/ban`;
    const heartbeatUrl = `${serverUrl}/api/heartbeat`;
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    return `--[[ Script Shield Protection Layer ]]
local _O={${ownerIds}}
local _W={${whitelistIds}}
local _B="${banUrl}"
local _HB="${heartbeatUrl}"
local _SID="${sessionId}"
local _A=true
local _SD=false

local _P=game:GetService("Players")
local _L=_P.LocalPlayer
local _S=game:GetService("StarterGui")
local _H=game:GetService("HttpService")

local function _n(t,x,d) 
    pcall(function() 
        _S:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) 
    end) 
end

local function _hw() 
    local s,r=pcall(function() 
        if gethwid then return gethwid() end 
        return "FB_"..tostring(_L.UserId) 
    end) 
    return s and r or "UNK" 
end

local function _isW(u) 
    for _,i in ipairs(_W) do 
        if u==i then return true end 
    end 
    return false 
end

local function _isO(u) 
    for _,i in ipairs(_O) do 
        if u==i then return true end 
    end 
    return false 
end

-- Owner check
for _,p in pairs(_P:GetPlayers()) do
    if _isO(p.UserId) and p~=_L then
        _n("⚠️","Owner detected",3)
        return
    end
end

_P.PlayerAdded:Connect(function(p)
    if _isO(p.UserId) then
        _n("⚠️","Owner joined",3)
        _A=false
    end
end)

-- Main script
${script}`;
}

// ==================== LOADER GENERATOR ====================
function getLoader(serverUrl) {
    return `--[[ Script Shield Loader ]]
local S="${serverUrl}"
local H=game:GetService("HttpService")
local P=game:GetService("Players")
local G=game:GetService("StarterGui")
local L=P.LocalPlayer

local function n(t,x,d) 
    pcall(function() 
        G:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) 
    end) 
end

local function hw() 
    local s,r=pcall(function() 
        if gethwid then return gethwid() end 
        return "FB_"..tostring(L.UserId) 
    end) 
    return s and r or "UNK" 
end

local function hp(u,d) 
    local r=(syn and syn.request) or request or http_request or (http and http.request) 
    if not r then 
        n("❌","No HTTP support",5) 
        return nil 
    end 
    
    local s,res=pcall(function() 
        return r({
            Url=u,
            Method="POST",
            Headers={
                ["Content-Type"]="application/json",
                ["User-Agent"]="Roblox/WinInet",
                ["x-hwid"]=hw(),
                ["x-roblox-id"]=tostring(L.UserId),
                ["x-place-id"]=tostring(game.PlaceId),
                ["x-job-id"]=game.JobId
            },
            Body=H:JSONEncode(d)
        }) 
    end) 
    
    if not s or res.StatusCode~=200 then 
        local e 
        pcall(function() e=H:JSONDecode(res.Body) end)
        if e and e.error then n("❌",e.error,5) end
        return nil 
    end 
    
    local ps,pd=pcall(function() return H:JSONDecode(res.Body) end) 
    return ps and pd or nil 
end

local function xd(d,k) 
    local r={} 
    for i=1,#d do 
        r[i]=string.char(bit32.bxor(d[i],string.byte(k,((i-1)%#k)+1))) 
    end 
    return table.concat(r) 
end

local function solve(p) 
    if p.type=="math" then 
        local a,b,c,op=p.puzzle.a,p.puzzle.b,p.puzzle.c,p.puzzle.op 
        if op=="+" then return(a+b)*c 
        elseif op=="-" then return(a-b)*c 
        elseif op=="*" then return(a*b)+c end 
    elseif p.type=="bitwise" then 
        local x,y,op=p.puzzle.x,p.puzzle.y,p.puzzle.op 
        if op=="xor" then return bit32.bxor(x,y) 
        elseif op=="and" then return bit32.band(x,y) 
        elseif op=="or" then return bit32.bor(x,y) end 
    elseif p.type=="sequence" then 
        local s=p.puzzle.seq 
        return s[4]+(s[2]-s[1]) 
    elseif p.puzzle.numbers then 
        local sum=0 
        for _,x in ipairs(p.puzzle.numbers) do sum=sum+x end 
        return sum 
    end 
    return 0 
end

local function main() 
    n("🔄","Connecting...",2) 
    
    local c=hp(S.."/api/auth/challenge",{
        userId=L.UserId,
        hwid=hw(),
        placeId=game.PlaceId
    }) 
    
    if not c or not c.success then return end 
    
    n("🔐","Verifying...",2) 
    
    local v=hp(S.."/api/auth/verify",{
        challengeId=c.challengeId,
        solution=solve(c),
        timestamp=os.time()
    }) 
    
    if not v or not v.success then return end 
    
    n("✅","Loading script...",2) 
    
    local fs 
    if v.mode=="raw" then 
        fs=v.script 
    else 
        local p={} 
        for i,ch in ipairs(v.chunks) do 
            p[i]=xd(ch,v.key) 
        end 
        fs=table.concat(p) 
    end 
    
    local fn,err=loadstring(fs) 
    if fn then 
        fs=nil v=nil c=nil 
        pcall(fn) 
    else 
        n("❌","Load failed",5) 
    end 
end

pcall(main)`;
}

// ==================== MIDDLEWARE ====================
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false
}));

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-admin-key', 'x-hwid', 'x-roblox-id', 'x-place-id', 'x-job-id', 'x-session-id']
}));

app.use(express.json({ limit: '10mb' }));
app.set('trust proxy', 1);

// Rate limiting
app.use(rateLimit({
    windowMs: 60000,
    max: 100,
    keyGenerator: r => getIP(r)
}));

// ==================== STATIC FILES ====================
const viewsPath = path.join(__dirname, 'views');

// Serve admin static files
app.use('/admin/css', express.static(path.join(viewsPath, 'admin/css')));
app.use('/admin/js', express.static(path.join(viewsPath, 'admin/js')));

// ==================== TRAP HTML ====================
const TRAP_HTML = fs.existsSync(path.join(viewsPath, 'trap/index.html'))
    ? fs.readFileSync(path.join(viewsPath, 'trap/index.html'), 'utf8')
    : `<!DOCTYPE html><html><head><title>403</title></head><body><h1>Access Denied</h1></body></html>`;

// ==================== BAN CHECK MIDDLEWARE ====================
app.use(async (req, res, next) => {
    const ban = await db.isBanned(null, getIP(req), null);
    if (ban.blocked) {
        const ct = getClientType(req);
        if (ct === 'browser') {
            return res.status(403).type('html').send(TRAP_HTML);
        }
        return res.status(403).type('text/plain').send(genFakeScript());
    }
    next();
});

// ==================== ROUTES ====================

// Admin panel
app.get('/admin', (req, res) => {
    const adminHtml = path.join(viewsPath, 'admin/index.html');
    if (fs.existsSync(adminHtml)) {
        res.sendFile(adminHtml);
    } else {
        res.status(404).send('Admin panel not found');
    }
});

// Root
app.get('/', (req, res) => {
    const ct = getClientType(req);
    if (ct === 'browser') {
        return res.status(403).type('html').send(TRAP_HTML);
    }
    if (ct === 'bot' || ct === 'unknown') {
        return res.status(403).type('text/plain').send(genFakeScript());
    }
    if (ct === 'blocked_executor') {
        return res.status(403).json({ error: 'Executor not allowed' });
    }
    res.json({ status: 'ok', version: '1.0.0' });
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', redis: db.isRedisConnected() });
});

// Loader
app.get(['/loader', '/api/loader.lua', '/api/loader', '/l'], async (req, res) => {
    const ct = getClientType(req);
    await logAccess(req, 'LOADER_' + ct.toUpperCase(), ct === 'executor');
    
    if (ct === 'browser') {
        return res.status(403).type('html').send(TRAP_HTML);
    }
    if (ct === 'bot' || ct === 'unknown' || ct === 'blocked_executor') {
        return res.status(403).type('text/plain').send(genFakeScript());
    }
    
    const url = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
    res.type('text/plain').send(getLoader(url));
});

// Challenge endpoint
app.post('/api/auth/challenge', async (req, res) => {
    const ct = getClientType(req);
    await logAccess(req, 'CHALLENGE_' + ct.toUpperCase(), ct === 'executor');
    
    if (ct === 'browser') {
        return res.status(403).type('html').send(TRAP_HTML);
    }
    if (ct === 'bot' || ct === 'unknown') {
        return res.status(403).type('text/plain').send(genFakeScript());
    }
    if (ct === 'blocked_executor') {
        return res.status(403).json({ success: false, error: 'Executor not allowed' });
    }
    
    const { userId, hwid, placeId } = req.body;
    
    if (!userId || !hwid || !placeId) {
        return res.status(400).json({ success: false, error: 'Missing fields' });
    }
    
    const uid = parseInt(userId);
    const pid = parseInt(placeId);
    
    if (isNaN(uid) || isNaN(pid)) {
        return res.status(400).json({ success: false, error: 'Invalid format' });
    }
    
    const ip = getIP(req);
    const ban = await db.isBanned(hwid, ip, uid);
    
    if (ban.blocked) {
        return res.status(403).json({ success: false, error: 'Banned: ' + ban.reason });
    }
    
    if (config.ALLOWED_PLACE_IDS && config.ALLOWED_PLACE_IDS.length > 0) {
        if (!config.ALLOWED_PLACE_IDS.includes(pid)) {
            return res.status(403).json({ success: false, error: 'Game not allowed' });
        }
    }
    
    const id = crypto.randomBytes(16).toString('hex');
    const chal = genChallenge();
    
    await db.setChallenge(id, {
        id,
        userId: uid,
        hwid,
        placeId: pid,
        ip,
        ...chal
    }, 120);
    
    res.json({
        success: true,
        challengeId: id,
        type: chal.type,
        puzzle: chal.puzzle,
        expiresIn: 120
    });
});

// Verify endpoint
app.post('/api/auth/verify', async (req, res) => {
    const ct = getClientType(req);
    await logAccess(req, 'VERIFY_' + ct.toUpperCase(), ct === 'executor');
    
    if (ct === 'browser') {
        return res.status(403).type('html').send(TRAP_HTML);
    }
    if (ct === 'bot' || ct === 'unknown') {
        return res.status(403).type('text/plain').send(genFakeScript());
    }
    if (ct === 'blocked_executor') {
        return res.status(403).json({ success: false, error: 'Executor not allowed' });
    }
    
    const { challengeId, solution, timestamp } = req.body;
    
    if (!challengeId || solution === undefined || !timestamp) {
        return res.status(400).json({ success: false, error: 'Missing fields' });
    }
    
    const challenge = await db.getChallenge(challengeId);
    
    if (!challenge) {
        return res.status(403).json({ success: false, error: 'Challenge expired' });
    }
    
    if (challenge.ip !== getIP(req)) {
        return res.status(403).json({ success: false, error: 'IP mismatch' });
    }
    
    if (parseInt(solution) !== challenge.answer) {
        return res.status(403).json({ success: false, error: 'Wrong solution' });
    }
    
    await db.deleteChallenge(challengeId);
    
    const script = await getScript();
    
    if (!script) {
        return res.status(500).json({ success: false, error: 'Script not configured' });
    }
    
    const url = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
    const wrapped = wrapScript(script, url);
    const isObf = config.SCRIPT_ALREADY_OBFUSCATED || isObfuscated(script);
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    SESSIONS.set(sessionId, {
        hwid: challenge.hwid,
        ip: challenge.ip,
        userId: challenge.userId,
        created: Date.now()
    });
    
    if (isObf) {
        return res.json({
            success: true,
            mode: 'raw',
            script: wrapped,
            sessionId,
            ownerIds: config.OWNER_USER_IDS || [],
            whitelistIds: config.WHITELIST_USER_IDS || []
        });
    }
    
    const key = genSessionKey(challenge.userId, challenge.hwid, timestamp, config.SECRET_KEY);
    const chunks = [];
    
    for (let i = 0; i < wrapped.length; i += 1500) {
        const chunk = wrapped.substring(i, i + 1500);
        const enc = [];
        for (let j = 0; j < chunk.length; j++) {
            enc.push(chunk.charCodeAt(j) ^ key.charCodeAt(j % key.length));
        }
        chunks.push(enc);
    }
    
    res.json({
        success: true,
        mode: 'encrypted',
        key,
        chunks,
        sessionId,
        ownerIds: config.OWNER_USER_IDS || [],
        whitelistIds: config.WHITELIST_USER_IDS || []
    });
});

// Heartbeat
app.post('/api/heartbeat', async (req, res) => {
    const { sessionId, hwid } = req.body;
    
    if (!sessionId || !hwid) {
        return res.json({ success: true, action: 'CONTINUE' });
    }
    
    const session = SESSIONS.get(sessionId);
    if (!session) {
        return res.json({ success: true, action: 'CONTINUE' });
    }
    
    const ban = await db.isBanned(hwid, getIP(req), session.userId);
    if (ban.blocked) {
        return res.json({ success: false, action: 'TERMINATE', reason: 'Banned' });
    }
    
    session.lastSeen = Date.now();
    res.json({ success: true, action: 'CONTINUE' });
});

// Ban endpoint (from script)
app.post('/api/ban', async (req, res) => {
    const { hwid, playerId, reason, toolsDetected, sessionId } = req.body;
    
    if (!hwid && !playerId) {
        return res.status(400).json({ error: 'Missing id' });
    }
    
    const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
    const banData = {
        ip: getIP(req),
        reason: reason || 'Auto',
        toolsDetected,
        banId,
        ts: new Date().toISOString()
    };
    
    if (hwid) {
        await db.addBan(hwid, { hwid, ...banData });
    }
    if (playerId) {
        await db.addBan(String(playerId), { playerId, ...banData });
    }
    if (sessionId) {
        SESSIONS.delete(sessionId);
    }
    
    await logAccess(req, 'BAN_ADDED', true, { hwid, playerId, reason });
    res.json({ success: true, banId });
});

// ==================== ADMIN API ====================

// Admin auth middleware
const adminAuth = (req, res, next) => {
    const key = req.headers['x-admin-key'] || req.query.key;
    
    // Debug logging (hapus setelah fix)
    console.log('[Admin Auth] Key received:', key ? 'Yes (' + key.length + ' chars)' : 'No');
    console.log('[Admin Auth] Config key exists:', !!config.ADMIN_KEY);
    
    if (!key) {
        return res.status(403).json({ 
            success: false,
            error: 'Unauthorized' 
        });
    }
    
    if (!config.ADMIN_KEY) {
        console.error('[Admin Auth] ADMIN_KEY not set in config!');
        return res.status(500).json({ 
            success: false,
            error: 'Server misconfigured' 
        });
    }
    
    const isValid = secureCompare(key, config.ADMIN_KEY);
    console.log('[Admin Auth] Key valid:', isValid);
    
    if (!isValid) {
        return res.status(403).json({ 
            success: false,
            error: 'Unauthorized' 
        });
    }
    
    next();
};

// Stats
app.get('/api/admin/stats', adminAuth, async (req, res) => {
    const stats = await db.getStats();
    res.json({ success: true, stats, sessions: SESSIONS.size });
});

// Logs
app.get('/api/admin/logs', adminAuth, async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 500);
    const logs = await db.getLogs(limit);
    res.json({ success: true, logs });
});

// Get all bans
app.get('/api/admin/bans', adminAuth, async (req, res) => {
    const bans = await db.getAllBans();
    res.json({ success: true, bans });
});

// Add ban
app.post('/api/admin/bans', adminAuth, async (req, res) => {
    const { hwid, ip, playerId, reason } = req.body;
    
    if (!hwid && !ip && !playerId) {
        return res.status(400).json({ error: 'At least one identifier required' });
    }
    
    const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
    const banData = {
        reason: reason || 'Manual ban',
        banId,
        ts: new Date().toISOString()
    };
    
    if (hwid) await db.addBan(hwid, { hwid, ...banData });
    if (playerId) await db.addBan(String(playerId), { playerId, ...banData });
    if (ip) await db.addBan(ip, { ip, ...banData });
    
    res.json({ success: true, banId });
});

// Remove ban by ID
app.delete('/api/admin/bans/:id', adminAuth, async (req, res) => {
    const removed = await db.removeBanById(req.params.id);
    res.json({ success: removed });
});

// Clear all bans
app.post('/api/admin/bans/clear', adminAuth, async (req, res) => {
    const count = await db.clearBans();
    res.json({ success: true, cleared: count });
});

// Clear cache
app.post('/api/admin/cache/clear', adminAuth, async (req, res) => {
    await db.setCachedScript(null);
    res.json({ success: true });
});

// Clear sessions
app.post('/api/admin/sessions/clear', adminAuth, async (req, res) => {
    const count = SESSIONS.size;
    SESSIONS.clear();
    res.json({ success: true, cleared: count });
});

// ==================== 404 HANDLER ====================
app.use('*', (req, res) => {
    const ct = getClientType(req);
    if (ct === 'browser') {
        return res.status(404).type('html').send(TRAP_HTML);
    }
    if (ct === 'bot' || ct === 'unknown' || ct === 'blocked_executor') {
        return res.status(403).type('text/plain').send(genFakeScript());
    }
    res.status(404).json({ error: 'Not found' });
});

// ==================== SESSION CLEANUP ====================
setInterval(() => {
    const now = Date.now();
    const maxAge = 7200000; // 2 hours
    
    for (const [key, session] of SESSIONS) {
        if (now - session.created > maxAge) {
            SESSIONS.delete(key);
        }
    }
}, 300000); // Every 5 minutes

// ==================== START SERVER ====================
const PORT = process.env.PORT || config.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('🛡️  ═══════════════════════════════════════');
    console.log('🛡️  Script Shield Server Started');
    console.log('🛡️  ═══════════════════════════════════════');
    console.log(`📡 Port: ${PORT}`);
    console.log(`🔗 Admin: http://localhost:${PORT}/admin`);
    console.log(`📦 Loader: http://localhost:${PORT}/loader`);
    console.log('🛡️  ═══════════════════════════════════════');
    console.log('');
});
