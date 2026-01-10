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

// === CONSTANTS ===
const BOT_PATTERNS = ['python', 'python-requests', 'aiohttp', 'httpx', 'curl', 'wget', 'libcurl', 'axios', 'node-fetch', 'got/', 'undici', 'superagent', 'java/', 'okhttp', 'apache-http', 'go-http', 'golang', 'ruby', 'perl', 'php/', 'postman', 'insomnia', 'paw/', 'bot', 'crawler', 'spider', 'scraper', 'slurp', 'googlebot', 'bingbot', 'yandex', 'facebookexternalhit', 'twitterbot', 'discordbot', 'telegrambot', 'burp', 'fiddler', 'charles', 'mitmproxy', 'nmap', 'nikto', 'sqlmap', 'nuclei', 'httpie', 'scanner', 'checker', 'monitor', 'probe'];
const B_HEADERS = ['sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-ch-ua', 'sec-ch-ua-mobile', 'upgrade-insecure-requests'];
const E_HEADERS = ['x-hwid', 'x-roblox-id', 'x-place-id', 'x-job-id', 'x-session-id'];
const ALLOWED_E = ['synapse', 'synapsex', 'script-ware', 'scriptware', 'delta', 'fluxus', 'krnl', 'oxygen', 'evon', 'hydrogen', 'vegax', 'trigon', 'comet', 'solara', 'wave', 'zorara', 'codex', 'celery', 'swift', 'sirhurt', 'electron', 'sentinel', 'coco', 'temple', 'valyse', 'nihon', 'jjsploit', 'arceus', 'roblox', 'wininet', 'win32'];

// === UTILS ===
function hmac(d, k) { return crypto.createHmac('sha256', k).update(d).digest('hex'); }
function secureCompare(a, b) { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; } }
function getIP(r) { return (r.headers['x-forwarded-for'] || '').split(',')[0].trim() || r.headers['x-real-ip'] || r.ip || '0.0.0.0'; }
function getHWID(r) { return r.headers['x-hwid'] || null; }
function genSessionKey(u, h, t, s) { return hmac(`${u}:${h}:${t}`, s).substring(0, 32); }

// === CLIENT DETECTION ===
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

// === FAKE SCRIPT ===
function genFakeScript() {
    const rS = (l) => { const c = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'; let s = ''; for (let i = 0; i < l; i++) s += c[Math.floor(Math.random() * c.length)]; return s; };
    const rH = (l) => { let h = ''; for (let i = 0; i < l; i++) h += Math.floor(Math.random() * 16).toString(16); return h; };
    return `--[[ Protected by Script Shield For Bot | Hash: ${rH(100)} ]]\nlocal ${rS(100)} = "${rS(320)}";\nlocal ${rS(5)} = function(${rS(4)})\n return string.byte(${rS(100)}) * ${Math.floor(Math.random() * 1000)};\nend;\n--[[ Obfuscation For Bøt]]`;
}

// === ENCRYPTION & CHUNKING ===
function encryptLoader(script, key) {
    const kB = Buffer.from(key);
    const sB = Buffer.from(script);
    const enc = [];
    for (let i = 0; i < sB.length; i++) enc.push(sB[i] ^ kB[i % kB.length]);
    return Buffer.from(enc).toString('base64');
}

function genLoaderKey(req) {
    const c = [req.headers['x-hwid'] || '', req.headers['x-roblox-id'] || '', req.headers['x-place-id'] || '', config.LOADER_KEY || config.SECRET_KEY];
    return crypto.createHash('md5').update(c.join(':')).digest('hex').substring(0, 16);
}

function chunkString(str, size) {
    const chunks = [];
    for (let i = 0; i < str.length; i += size) chunks.push(str.substring(i, i + size));
    return chunks;
}

function encryptChunk(c, k) {
    const e = [];
    for (let i = 0; i < c.length; i++) {
        const cc = c.charCodeAt(i);
        const kc = k.charCodeAt(i % k.length);
        e.push((cc ^ kc) & 255);
    }
    return e;
}

function generateChunkKeys(baseKey, count) {
    const keys = [];
    for (let i = 0; i < count; i++) keys.push(crypto.createHash('md5').update(baseKey + ':' + i).digest('hex'));
    return keys;
}

async function prepareChunks(s, ch) {
    const count = config.CHUNK_COUNT || 3;
    const size = Math.ceil(s.length / count);
    const chunks = chunkString(s, size);
    const base = crypto.createHash('sha256').update((ch.hwid || '') + (ch.userId || '') + config.SECRET_KEY).digest('hex');
    const keys = generateChunkKeys(base, chunks.length);
    return {
        chunks: chunks.map((c, i) => ({ index: i, data: encryptChunk(c, keys[i]) })),
        keys,
        totalChunks: chunks.length
    };
}

// === SUSPEND ===
async function suspendUser(type, value, data) {
    const entry = { ...data, type, value, suspendedAt: new Date().toISOString(), expiresAt: data.duration ? new Date(Date.now() + parseInt(data.duration) * 1000).toISOString() : null };
    if (type === 'hwid') suspendedUsers.hwids.set(String(value), entry);
    else if (type === 'userId') suspendedUsers.userIds.set(String(value), entry);
    else if (type === 'session') suspendedUsers.sessions.set(String(value), entry);
    await db.addSuspend(type, String(value), entry);
    webhook.suspicious({ userId: data.userId, hwid: data.hwid, ip: data.ip, reason: 'Suspended: ' + (data.reason || 'Admin action'), tool: 'N/A', action: 'Suspended' }).catch(() => { });
}

async function unsuspendUser(type, value) {
    if (type === 'hwid') suspendedUsers.hwids.delete(String(value));
    else if (type === 'userId') suspendedUsers.userIds.delete(String(value));
    else if (type === 'session') suspendedUsers.sessions.delete(String(value));
    await db.removeSuspend(type, String(value));
}

function checkSuspended(h, u, sid) {
    const now = Date.now();
    const check = (m, k) => {
        if (m.has(k)) {
            const s = m.get(k);
            if (!s.expiresAt || new Date(s.expiresAt).getTime() > now) return { suspended: true, reason: s.reason || 'Suspended' };
            m.delete(k);
        }
        return null;
    };
    return check(suspendedUsers.sessions, sid) || check(suspendedUsers.hwids, h) || check(suspendedUsers.userIds, String(u));
}

async function loadSuspendedFromDB() {
    const all = await db.getAllSuspends();
    if (all && all.length > 0) {
        all.forEach(s => {
            if (s.type === 'hwid') suspendedUsers.hwids.set(s.value, s);
            else if (s.type === 'userId') suspendedUsers.userIds.set(s.value, s);
            else if (s.type === 'session') suspendedUsers.sessions.set(s.value, s);
        });
    }
}

// === LOGGING & SCRIPT ===
async function logAccess(r, a, s, d = {}) {
    const log = { ip: getIP(r), hwid: getHWID(r), ua: (r.headers['user-agent'] || '').substring(0, 100), action: a, success: s, client: getClientType(r), ts: new Date().toISOString(), ...d };
    await db.addLog(log);
    return log;
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
    const c = await db.getCachedScript();
    if (c) return c;
    if (!config.SCRIPT_SOURCE_URL) return null;
    try {
        const res = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 15000 });
        if (res.data) {
            await db.setCachedScript(res.data);
            return res.data;
        }
    } catch (e) { console.error('Script fetch error:', e.message); }
    return null;
}

function isObfuscated(s) {
    if (!s) return false;
    return [/Luraph/i, /Moonsec/i, /IronBrew/i, /Prometheus/i, /PSU/i].some(r => r.test(s.substring(0, 500)));
}

// === WRAPPER - FIXED ANTI-SPY ===
function wrapScript(s, serverUrl) {
    const o = (config.OWNER_USER_IDS || []).map(id => `[${id}]=true`).join(',');
    const w = (config.WHITELIST_USER_IDS || []).map(id => `[${id}]=true`).join(',');
    const sid = crypto.randomBytes(16).toString('hex');
    const antiSpyEnabled = config.ANTI_SPY_ENABLED !== false;
    const autoBan = config.AUTO_BAN_SPYTOOLS === true;

    return `--[[ Shield Protection Layer v2.1 ]]

-- ═══════════════════════════════════════════════════════════
-- CONFIGURATION
-- ═══════════════════════════════════════════════════════════
local _CFG = {
    o = {${o}},
    w = {${w}},
    banUrl = "${serverUrl}/api/ban",
    webhookUrl = "${serverUrl}/api/webhook/suspicious",
    hbUrl = "${serverUrl}/api/heartbeat",
    sid = "${sid}",
    as = ${antiSpyEnabled},
    ab = ${autoBan},
    hbi = 45
}

-- ═══════════════════════════════════════════════════════════
-- SERVICES & VARIABLES
-- ═══════════════════════════════════════════════════════════
local Players = game:GetService("Players")
local CoreGui = game:GetService("CoreGui")
local StarterGui = game:GetService("StarterGui")
local HttpService = game:GetService("HttpService")

local LocalPlayer = Players.LocalPlayer
local _ACTIVE = true
local _CONNECTIONS = {}
local _HB_FAILS = 0
local _INITIAL_GUIS = {}
local _DETECTED_CACHE = {}

-- ═══════════════════════════════════════════════════════════
-- BLACKLIST - Tools yang akan di-kick jika AKTIF
-- ═══════════════════════════════════════════════════════════
local BLACKLIST = {
    -- Spy Tools
    "simplespy", "remotespy", "httpspy", "synspy", "mspy",
    -- Dex/Explorer
    "dex", "dexv2", "dexv3", "dexv4", "darkdex", "dexexplorer",
    -- Infinite Yield
    "infiniteyield", "infinite yield", "iy", "iy_fe",
    -- Remote/HTTP
    "remotelogger", "httplogger", "remotedumper",
    -- Dumper/Decompile
    "scriptdumper", "dumper", "decompiler", "unluac",
    "saveinstance", "saveplace",
    -- Other spy/admin tools
    "hydroxide", "unnamed", "fates", "fatality",
    "aspect", "solar", "console", "output",
    "cmdx", "cmdbar", "adminpanel", "adminmenu"
}

-- Whitelist - GUI yang aman (Roblox default + executor)
local SAFE_PATTERNS = {
    "roblox", "coregui", "topbar", "bubble", "chat",
    "playerlist", "health", "purchase", "prompt",
    "notification", "menu", "freecam", "camera"
}

-- ═══════════════════════════════════════════════════════════
-- UTILITY FUNCTIONS
-- ═══════════════════════════════════════════════════════════
local function Notify(title, text, duration)
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title,
            Text = text,
            Duration = duration or 3
        })
    end)
end

local function GetHWID()
    local success, result = pcall(function()
        if gethwid then return gethwid() end
        if getexecutorname then return getexecutorname() .. tostring(LocalPlayer.UserId) end
        return "NK_" .. tostring(LocalPlayer.UserId)
    end)
    return success and result or "UNKNOWN"
end

local function HttpPost(url, data)
    local req = (syn and syn.request) or request or http_request or (http and http.request)
    if not req then return end
    pcall(function()
        req({
            Url = url,
            Method = "POST",
            Headers = {
                ["Content-Type"] = "application/json",
                ["User-Agent"] = "Roblox/WinInet",
                ["x-hwid"] = GetHWID(),
                ["x-roblox-id"] = tostring(LocalPlayer.UserId),
                ["x-session-id"] = _CFG.sid
            },
            Body = HttpService:JSONEncode(data)
        })
    end)
end

local function IsWhitelisted(userId)
    return _CFG.w[userId] == true
end

local function IsOwner(userId)
    return _CFG.o[userId] == true
end

-- ═══════════════════════════════════════════════════════════
-- KICK/CLEANUP FUNCTION
-- ═══════════════════════════════════════════════════════════
local function Terminate(reason)
    if not _ACTIVE then return end
    _ACTIVE = false
    
    Notify("🚫 Security", reason or "Terminated", 5)
    
    -- Disconnect semua connections
    for i = #_CONNECTIONS, 1, -1 do
        pcall(function() _CONNECTIONS[i]:Disconnect() end)
    end
    
    task.wait(0.3)
    
    -- Kill character
    pcall(function()
        if LocalPlayer.Character then
            LocalPlayer.Character:BreakJoints()
        end
    end)
    
    task.wait(0.3)
    
    -- Kick player
    pcall(function()
        LocalPlayer:Kick(reason or "Security Violation")
    end)
end

-- ═══════════════════════════════════════════════════════════
-- SPY DETECTION FUNCTIONS
-- ═══════════════════════════════════════════════════════════
local function IsSafeGui(name)
    local lowerName = name:lower()
    for _, pattern in ipairs(SAFE_PATTERNS) do
        if lowerName:find(pattern) then
            return true
        end
    end
    return false
end

local function IsSpyTool(name)
    local lowerName = name:lower()
    
    -- Skip jika safe pattern
    if IsSafeGui(name) then
        return false, nil
    end
    
    -- Check blacklist
    for _, banned in ipairs(BLACKLIST) do
        if lowerName:find(banned:lower()) then
            return true, banned
        end
    end
    
    -- Check suspicious patterns (GUI dengan nama versi)
    if lowerName:match("v%d") or lowerName:match("v_%d") then
        if lowerName:find("spy") or lowerName:find("remote") or lowerName:find("dex") or lowerName:find("dump") then
            return true, "suspicious_version"
        end
    end
    
    return false, nil
end

local function ScanContainer(container, source)
    if not container then return false end
    
    local detected = false
    
    pcall(function()
        for _, gui in pairs(container:GetChildren()) do
            if gui:IsA("ScreenGui") or gui:IsA("Frame") or gui:IsA("Folder") then
                local guiName = gui.Name
                local lowerName = guiName:lower()
                
                -- Skip jika sudah ada sebelum script load
                if _INITIAL_GUIS[lowerName] then
                    continue
                end
                
                -- Skip jika sudah pernah di-detect (prevent spam)
                if _DETECTED_CACHE[lowerName] then
                    continue
                end
                
                local isSpy, matched = IsSpyTool(guiName)
                if isSpy then
                    _DETECTED_CACHE[lowerName] = true
                    detected = true
                    
                    print("[Shield] 🚨 DETECTED:", guiName, "| Matched:", matched, "| Source:", source)
                    
                    -- Report to server
                    HttpPost(_CFG.webhookUrl, {
                        userId = LocalPlayer.UserId,
                        tool = guiName,
                        matched = matched,
                        source = source,
                        sessionId = _CFG.sid
                    })
                    
                    -- Auto-ban if enabled
                    if _CFG.ab then
                        HttpPost(_CFG.banUrl, {
                            hwid = GetHWID(),
                            playerId = LocalPlayer.UserId,
                            reason = "Spy Tool: " .. guiName,
                            sessionId = _CFG.sid
                        })
                    end
                    
                    Terminate("Security Violation: " .. guiName)
                    return true
                end
            end
        end
    end)
    
    return detected
end

local function ScanNilInstances()
    if not getnilinstances then return false end
    
    local detected = false
    
    pcall(function()
        for _, instance in pairs(getnilinstances()) do
            if instance:IsA("ScreenGui") then
                local guiName = instance.Name
                local lowerName = guiName:lower()
                
                if _INITIAL_GUIS[lowerName] or _DETECTED_CACHE[lowerName] then
                    continue
                end
                
                local isSpy, matched = IsSpyTool(guiName)
                if isSpy then
                    _DETECTED_CACHE[lowerName] = true
                    detected = true
                    
                    print("[Shield] 🚨 DETECTED (Hidden):", guiName)
                    
                    HttpPost(_CFG.webhookUrl, {
                        userId = LocalPlayer.UserId,
                        tool = guiName,
                        source = "NilInstance",
                        sessionId = _CFG.sid
                    })
                    
                    if _CFG.ab then
                        HttpPost(_CFG.banUrl, {
                            hwid = GetHWID(),
                            playerId = LocalPlayer.UserId,
                            reason = "Hidden Spy: " .. guiName,
                            sessionId = _CFG.sid
                        })
                    end
                    
                    Terminate("Security Violation: " .. guiName)
                    return true
                end
            end
        end
    end)
    
    return detected
end

local function FullScan()
    if not _CFG.as or IsWhitelisted(LocalPlayer.UserId) then return false end
    
    -- Scan CoreGui
    if ScanContainer(CoreGui, "CoreGui") then return true end
    
    -- Scan PlayerGui
    if LocalPlayer:FindFirstChild("PlayerGui") then
        if ScanContainer(LocalPlayer.PlayerGui, "PlayerGui") then return true end
    end
    
    -- Scan Nil Instances
    if ScanNilInstances() then return true end
    
    return false
end

-- ═══════════════════════════════════════════════════════════
-- INITIAL CHECK - Sebelum script load
-- ═══════════════════════════════════════════════════════════
local function TakeSnapshot()
    pcall(function()
        -- Snapshot CoreGui
        for _, gui in pairs(CoreGui:GetChildren()) do
            _INITIAL_GUIS[gui.Name:lower()] = true
        end
        
        -- Snapshot PlayerGui
        if LocalPlayer:FindFirstChild("PlayerGui") then
            for _, gui in pairs(LocalPlayer.PlayerGui:GetChildren()) do
                _INITIAL_GUIS[gui.Name:lower()] = true
            end
        end
    end)
end

local function PreCheck()
    if not _CFG.as or IsWhitelisted(LocalPlayer.UserId) then
        return true -- Allowed to continue
    end
    
    print("[Shield] 🔍 Running pre-check for active spy tools...")
    
    -- Cek apakah ada spy tool yang SUDAH AKTIF sebelum script ini load
    local foundSpy = false
    
    pcall(function()
        -- Check CoreGui
        for _, gui in pairs(CoreGui:GetChildren()) do
            local isSpy, matched = IsSpyTool(gui.Name)
            if isSpy then
                foundSpy = true
                print("[Shield] 🚨 PRE-CHECK FAILED:", gui.Name, "already active!")
                
                HttpPost(_CFG.webhookUrl, {
                    userId = LocalPlayer.UserId,
                    tool = gui.Name,
                    matched = matched,
                    source = "PreCheck",
                    sessionId = _CFG.sid
                })
                
                if _CFG.ab then
                    HttpPost(_CFG.banUrl, {
                        hwid = GetHWID(),
                        playerId = LocalPlayer.UserId,
                        reason = "Pre-existing Spy: " .. gui.Name,
                        sessionId = _CFG.sid
                    })
                end
                
                return
            end
        end
        
        -- Check PlayerGui
        if LocalPlayer:FindFirstChild("PlayerGui") then
            for _, gui in pairs(LocalPlayer.PlayerGui:GetChildren()) do
                local isSpy, matched = IsSpyTool(gui.Name)
                if isSpy then
                    foundSpy = true
                    print("[Shield] 🚨 PRE-CHECK FAILED:", gui.Name, "already active!")
                    
                    HttpPost(_CFG.webhookUrl, {
                        userId = LocalPlayer.UserId,
                        tool = gui.Name,
                        source = "PreCheck",
                        sessionId = _CFG.sid
                    })
                    
                    if _CFG.ab then
                        HttpPost(_CFG.banUrl, {
                            hwid = GetHWID(),
                            playerId = LocalPlayer.UserId,
                            reason = "Pre-existing Spy: " .. gui.Name,
                            sessionId = _CFG.sid
                        })
                    end
                    
                    return
                end
            end
        end
        
        -- Check nil instances
        if getnilinstances then
            for _, instance in pairs(getnilinstances()) do
                if instance:IsA("ScreenGui") then
                    local isSpy, matched = IsSpyTool(instance.Name)
                    if isSpy then
                        foundSpy = true
                        print("[Shield] 🚨 PRE-CHECK FAILED (Hidden):", instance.Name)
                        
                        HttpPost(_CFG.webhookUrl, {
                            userId = LocalPlayer.UserId,
                            tool = instance.Name,
                            source = "PreCheck_Nil",
                            sessionId = _CFG.sid
                        })
                        
                        if _CFG.ab then
                            HttpPost(_CFG.banUrl, {
                                hwid = GetHWID(),
                                playerId = LocalPlayer.UserId,
                                reason = "Hidden Pre-existing Spy: " .. instance.Name,
                                sessionId = _CFG.sid
                            })
                        end
                        
                        return
                    end
                end
            end
        end
    end)
    
    if foundSpy then
        Terminate("Spy tool detected - Script blocked")
        return false
    end
    
    print("[Shield] ✅ Pre-check passed - No active spy tools")
    return true
end

-- ═══════════════════════════════════════════════════════════
-- OWNER PROTECTION
-- ═══════════════════════════════════════════════════════════
local function CheckOwnerPresence()
    for _, player in pairs(Players:GetPlayers()) do
        if IsOwner(player.UserId) and player ~= LocalPlayer then
            return false
        end
    end
    return true
end

local function StartOwnerMonitor()
    table.insert(_CONNECTIONS, Players.PlayerAdded:Connect(function(player)
        task.wait(1)
        if IsOwner(player.UserId) and _ACTIVE then
            Terminate("Owner joined the server")
        end
    end))
end

-- ═══════════════════════════════════════════════════════════
-- ANTI-SPY MONITOR (Real-time)
-- ═══════════════════════════════════════════════════════════
local function StartAntiSpy()
    if not _CFG.as then return end
    
    -- Take snapshot setelah pre-check
    TakeSnapshot()
    
    -- Monitor CoreGui ChildAdded (real-time detection)
    table.insert(_CONNECTIONS, CoreGui.ChildAdded:Connect(function(child)
        task.wait(0.1)
        if not _ACTIVE then return end
        
        local guiName = child.Name
        local lowerName = guiName:lower()
        
        -- Skip jika sudah di-snapshot atau sudah detect
        if _INITIAL_GUIS[lowerName] or _DETECTED_CACHE[lowerName] then return end
        
        local isSpy, matched = IsSpyTool(guiName)
        if isSpy then
            _DETECTED_CACHE[lowerName] = true
            
            print("[Shield] 🚨 REALTIME DETECTED:", guiName)
            
            HttpPost(_CFG.webhookUrl, {
                userId = LocalPlayer.UserId,
                tool = guiName,
                matched = matched,
                source = "Realtime",
                sessionId = _CFG.sid
            })
            
            if _CFG.ab then
                HttpPost(_CFG.banUrl, {
                    hwid = GetHWID(),
                    playerId = LocalPlayer.UserId,
                    reason = "Spy Tool: " .. guiName,
                    sessionId = _CFG.sid
                })
            end
            
            Terminate("Security Violation: " .. guiName)
        end
    end))
    
    -- Monitor PlayerGui jika ada
    if LocalPlayer:FindFirstChild("PlayerGui") then
        table.insert(_CONNECTIONS, LocalPlayer.PlayerGui.ChildAdded:Connect(function(child)
            task.wait(0.1)
            if not _ACTIVE then return end
            
            local guiName = child.Name
            local lowerName = guiName:lower()
            
            if _INITIAL_GUIS[lowerName] or _DETECTED_CACHE[lowerName] then return end
            
            local isSpy, matched = IsSpyTool(guiName)
            if isSpy then
                _DETECTED_CACHE[lowerName] = true
                
                print("[Shield] 🚨 REALTIME DETECTED (PlayerGui):", guiName)
                
                HttpPost(_CFG.webhookUrl, {
                    userId = LocalPlayer.UserId,
                    tool = guiName,
                    source = "Realtime_PlayerGui",
                    sessionId = _CFG.sid
                })
                
                if _CFG.ab then
                    HttpPost(_CFG.banUrl, {
                        hwid = GetHWID(),
                        playerId = LocalPlayer.UserId,
                        reason = "Spy Tool: " .. guiName,
                        sessionId = _CFG.sid
                    })
                end
                
                Terminate("Security Violation: " .. guiName)
            end
        end))
    end
    
    -- Periodic full scan (backup, setiap 5 detik)
    task.spawn(function()
        task.wait(3)
        while _ACTIVE do
            FullScan()
            task.wait(5)
        end
    end)
    
    print("[Shield] 👁️ Anti-spy monitor started")
end

-- ═══════════════════════════════════════════════════════════
-- HEARTBEAT
-- ═══════════════════════════════════════════════════════════
local function StartHeartbeat()
    task.spawn(function()
        task.wait(10)
        while _ACTIVE do
            local response
            local req = (syn and syn.request) or request or http_request or (http and http.request)
            
            if req then
                local success, result = pcall(function()
                    return req({
                        Url = _CFG.hbUrl,
                        Method = "POST",
                        Headers = {
                            ["Content-Type"] = "application/json",
                            ["x-session-id"] = _CFG.sid
                        },
                        Body = HttpService:JSONEncode({
                            sessionId = _CFG.sid,
                            hwid = GetHWID(),
                            userId = LocalPlayer.UserId
                        })
                    })
                end)
                
                if success and result and result.StatusCode == 200 then
                    local ok, body = pcall(function()
                        return HttpService:JSONDecode(result.Body)
                    end)
                    if ok then response = body end
                end
            end
            
            if response then
                _HB_FAILS = 0
                if response.action == "TERMINATE" then
                    Terminate(response.reason or "Session terminated")
                    break
                elseif response.action == "MESSAGE" and response.message then
                    Notify("📢 Message", response.message, 5)
                end
            else
                _HB_FAILS = _HB_FAILS + 1
                if _HB_FAILS >= 5 then
                    Terminate("Connection lost to server")
                    break
                end
            end
            
            task.wait(_CFG.hbi)
        end
    end)
end

-- ═══════════════════════════════════════════════════════════
-- MAIN EXECUTION
-- ═══════════════════════════════════════════════════════════

-- Step 1: Check owner presence
if not CheckOwnerPresence() then
    Notify("⚠️ Warning", "Owner is in this server!", 5)
    return
end

-- Step 2: Pre-check untuk spy tools yang sudah aktif
if not PreCheck() then
    -- Jika ada spy tool aktif, script tidak akan load
    return
end

-- Step 3: Start protections
StartOwnerMonitor()
StartAntiSpy()
StartHeartbeat()

Notify("🛡️ Shield", "Protection active", 3)
print("[Shield] 🛡️ Protection active for user:", LocalPlayer.UserId)
print("[Shield] 📋 Session ID:", _CFG.sid)

-- ═══════════════════════════════════════════════════════════
-- YOUR SCRIPT LOADS HERE (only if all checks passed)
-- ═══════════════════════════════════════════════════════════

${s}`;
}

// === LOADERS ===
function getLoader(url) {
    return `local S="${url}" local H=game:GetService("HttpService") local P=game:GetService("Players") local L=P.LocalPlayer 
local function n(t,x,d)pcall(function()game:GetService("StarterGui"):SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3})end)end 
local function hp(u,d)local r=(syn and syn.request)or request or http_request or(http and http.request)if not r then return nil end;local s,res=pcall(function()return r({Url=u,Method="POST",Headers={["Content-Type"]="application/json",["User-Agent"]="Roblox/WinInet",["x-hwid"]=(gethwid and gethwid() or "UNK"),["x-roblox-id"]=tostring(L.UserId),["x-place-id"]=tostring(game.PlaceId)},Body=H:JSONEncode(d)})end)
if s and res and res.StatusCode==200 then local ok,body=pcall(function()return H:JSONDecode(res.Body)end) if ok then return body end end return nil end 
local function xd(data,key)local r={} for i=1,#data do local b=data[i] local k=string.byte(key,((i-1)%#key)+1) table.insert(r, string.char(bit32.bxor(b,k))) end return table.concat(r) end
local function sv(p)if not p or not p.type then return 0 end;if p.type=="math"then local a,b,c,op=p.puzzle.a,p.puzzle.b,p.puzzle.c,p.puzzle.op;if op=="+"then return(a+b)*c elseif op=="-"then return(a-b)*c else return(a*b)+c end elseif p.type=="bitwise"then local x,y,op=p.puzzle.x,p.puzzle.y,p.puzzle.op;if op=="xor"then return bit32.bxor(x,y)elseif op=="and"then return bit32.band(x,y)else return bit32.bor(x,y)end elseif p.type=="sequence"then local s=p.puzzle.seq;return s[4]+(s[2]-s[1])elseif p.puzzle and p.puzzle.numbers then local sum=0;for _,x in ipairs(p.puzzle.numbers)do sum=sum+x end;return sum end;return 0 end 
local function asm(v)if not v then return nil end;if v.mode=="raw" then return v.script end;if v.mode=="chunked" then local p={} for _,c in ipairs(v.chunks) do local k=v.keys[c.index+1] if k and c.data then p[c.index+1]=xd(c.data,k) end end return table.concat(p) end return nil end
n("🔄","Connecting...",2) local c=hp(S.."/api/auth/challenge",{userId=L.UserId,hwid=(gethwid and gethwid() or "UNK"),placeId=game.PlaceId})
if c and c.success then n("🔐","Verifying...",2) local v=hp(S.."/api/auth/verify",{challengeId=c.challengeId,solution=sv(c),timestamp=os.time()})
if v and v.success then n("📦","Loading...",2) local fs=asm(v) if fs then local f,e=loadstring(fs) if f then pcall(f) n("✅","Success!",2) else n("❌","Syntax: "..(e or "?"),5) end else n("❌","Assembly Failed",5) end else n("❌","Verify Failed",5) end else n("❌","Conn Failed",5) end`;
}

function getEncodedLoader(url, req) {
    const key = genLoaderKey(req);
    const enc = encryptLoader(getLoader(url), key);
    return `local k="${key}"local d="${enc}"local function x(s,k)local r={}local b={}for i=1,#s do b[i]=s:byte(i)end;for i=1,#b do r[i]=string.char(bit32.bxor(b[i],k:byte((i-1)%#k+1)))end;return table.concat(r)end;local function b(s)local t={}local c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"for i=1,64 do t[c:sub(i,i)]=i-1 end;s=s:gsub("[^"..c.."=]","")local r={}local n=1;for i=1,#s,4 do local a,b,c,d=t[s:sub(i,i)]or 0,t[s:sub(i+1,i+1)]or 0,t[s:sub(i+2,i+2)]or 0,t[s:sub(i+3,i+3)]or 0;local v=a*262144+b*4096+c*64+d;r[n]=string.char(bit32.rshift(v,16)%256)n=n+1;if s:sub(i+2,i+2)~="="then r[n]=string.char(bit32.rshift(v,8)%256)n=n+1 end;if s:sub(i+3,i+3)~="="then r[n]=string.char(v%256)n=n+1 end end;return table.concat(r)end;loadstring(x(b(d),k))()`;
}

// === CONFIG & INIT ===
const viewsPath = path.join(__dirname, 'views');
const LOADER_HTML = fs.existsSync(path.join(viewsPath, 'loader/index.html')) ? fs.readFileSync(path.join(viewsPath, 'loader/index.html'), 'utf8') : `<h1>Loader</h1>`;
const TRAP_HTML = fs.existsSync(path.join(viewsPath, 'trap/index.html')) ? fs.readFileSync(path.join(viewsPath, 'trap/index.html'), 'utf8') : `<!DOCTYPE html><html><head><title>403</title></head><body style="background:#0a0a0f;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif"><div style="text-align:center"><h1 style="font-size:60px">🛡️</h1><h2 style="color:#ef4444">Access Denied</h2><p style="color:#666">HTTP 403</p></div></body></html>`;

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'x-admin-key', 'x-hwid', 'x-roblox-id', 'x-place-id', 'x-job-id', 'x-session-id'] }));
app.use(express.json({ limit: '10mb' }));
app.set('trust proxy', 1);
app.use(rateLimit({ windowMs: 60000, max: 100, keyGenerator: r => getIP(r) }));
app.use('/admin/css', express.static(path.join(viewsPath, 'admin/css')));
app.use('/admin/js', express.static(path.join(viewsPath, 'admin/js')));

// === MIDDLEWARE ===
app.use(async (req, res, next) => {
    const adminPath = config.ADMIN_PATH || '/admin';
    if (req.path.startsWith(adminPath) || req.path === '/health') return next();
    if (req.path === '/loader' || req.path === '/l' || req.path === '/api/loader' || req.path === '/api/loader.lua') return next();
    
    const ban = await db.isBanned(null, getIP(req), null);
    if (ban.blocked) {
        if (getClientType(req) === 'browser') return res.status(403).type('html').send(TRAP_HTML);
        return res.status(403).type('text/plain').send(genFakeScript());
    }
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

// === LOADER ENDPOINT - DUAL BOT HANDLING ===
app.get(['/loader', '/api/loader.lua', '/api/loader', '/l'], async (req, res) => {
    const ct = getClientType(req);
    const ip = getIP(req);
    const hwid = getHWID(req);
    const userId = req.headers['x-roblox-id'] || null;
    
    // PRIORITY 1: Cek BAN → 403 Error
    const ban = await db.isBanned(hwid, ip, userId);
    if (ban.blocked) {
        console.log(`[Loader] 🚫 BANNED - IP: ${ip}, Reason: ${ban.reason}`);
        await logAccess(req, 'LOADER_BANNED', false, { clientType: ct, ip, hwid, userId, banReason: ban.reason });
        
        if (ct === 'browser') return res.status(403).type('html').send(TRAP_HTML);
        return res.status(403).json({ success: false, error: 'Access Denied', code: 'BANNED', message: 'Your access has been permanently revoked.' });
    }
    
    // PRIORITY 2: Browser → Loader HTML
    if (ct === 'browser') return res.status(200).type('html').send(LOADER_HTML);
    
    // PRIORITY 3: Bot (not banned) → Fake Script
    if (shouldBlock(req)) {
        console.log(`[Loader] 🤖 BOT DETECTED - Type: ${ct}, IP: ${ip} → Fake Script`);
        await logAccess(req, 'LOADER_BOT_FAKE', false, { clientType: ct, ip });
        return res.status(200).type('text/plain').send(genFakeScript());
    }
    
    // PRIORITY 4: Valid executor → Real Loader
    console.log(`[Loader] ✅ Valid executor - IP: ${ip}, UserID: ${userId}`);
    await logAccess(req, 'LOADER', true, { clientType: ct, userId });
    
    const isWL = await checkWhitelist(hwid, userId, req);
    const url = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
    
    if (config.ENCODE_LOADER !== false && !isWL) res.type('text/plain').send(getEncodedLoader(url, req));
    else res.type('text/plain').send(getLoader(url));
});

app.post('/api/auth/challenge', async (req, res) => {
    const ct = getClientType(req);
    if (shouldBlock(req)) { await logAccess(req, 'CHALLENGE_BLOCKED', false, { clientType: ct }); return res.status(403).json({ success: false, error: 'Access denied' }); }
    const { userId, hwid, placeId } = req.body;
    if (!userId || !placeId) return res.status(400).json({ success: false, error: 'Missing fields' });
    if (config.REQUIRE_HWID && !hwid) return res.status(400).json({ success: false, error: 'HWID required' });
    
    const uid = parseInt(userId), pid = parseInt(placeId);
    if (isNaN(uid) || isNaN(pid)) return res.status(400).json({ success: false, error: 'Invalid format' });
    
    const ip = getIP(req);
    const isWL = await checkWhitelist(hwid, uid, req);
    const susp = checkSuspended(hwid, uid, null);
    
    if (susp) return res.json({ success: false, error: 'Suspended: ' + susp.reason });
    if (!isWL) { const ban = await db.isBanned(hwid, ip, uid); if (ban.blocked) return res.json({ success: false, error: 'Banned: ' + ban.reason }); }
    if (config.ALLOWED_PLACE_IDS && config.ALLOWED_PLACE_IDS.length > 0 && !config.ALLOWED_PLACE_IDS.includes(pid) && !isWL) return res.status(403).json({ success: false, error: 'Game not authorized' });
    
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
    if (!script) return res.status(500).json({ success: false, error: 'Script not configured' });
    
    const url = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
    const wrapped = wrapScript(script, url);
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    SESSIONS.set(sessionId, { hwid: challenge.hwid, ip: challenge.ip, userId: challenge.userId, placeId: challenge.placeId, created: Date.now(), lastSeen: Date.now() });
    webhook.execution({ userId: challenge.userId, hwid: challenge.hwid, placeId: challenge.placeId, ip: challenge.ip, executor: req.headers['user-agent'] }).catch(() => {});
    await logAccess(req, 'VERIFY_SUCCESS', true, { userId: challenge.userId });
    
    if (config.CHUNK_DELIVERY !== false || challenge.whitelisted) { const ckd = await prepareChunks(wrapped, challenge); return res.json({ success: true, mode: 'chunked', chunks: ckd.chunks, keys: ckd.keys, sessionId: sessionId }); }
    
    const isObf = isObfuscated(script) || config.SCRIPT_ALREADY_OBFUSCATED;
    if (isObf) return res.json({ success: true, mode: 'raw', script: wrapped, sessionId });
    
    const key = genSessionKey(challenge.userId, challenge.hwid, timestamp, config.SECRET_KEY);
    const chunks = [];
    for (let i = 0; i < wrapped.length; i += 1500) { const chunk = wrapped.substring(i, i + 1500); const enc = []; for (let j = 0; j < chunk.length; j++) enc.push(chunk.charCodeAt(j) ^ key.charCodeAt(j % key.length)); chunks.push(enc); }
    res.json({ success: true, mode: 'encrypted', key, chunks, sessionId });
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
    const { userId, hwid, tool, sessionId, source, matched } = req.body;
    console.log(`[Webhook] 🚨 Suspicious activity - User: ${userId}, Tool: ${tool}, Source: ${source}, Matched: ${matched}`);
    await logAccess(req, 'SUSPICIOUS', false, { userId, hwid, tool, source, matched });
    webhook.suspicious({ userId, hwid, ip: getIP(req), reason: 'Spy tool detected: ' + tool, tool, action: config.AUTO_BAN_SPYTOOLS ? 'Auto-banned' : 'Kicked' }).catch(() => {});
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
    console.log(`[Ban] 🔨 User banned - HWID: ${hwid}, PlayerID: ${playerId}, Reason: ${reason}`);
    await logAccess(req, 'BAN_ADDED', true, { hwid, playerId, reason });
    webhook.ban({ userId: playerId, hwid, ip: getIP(req), reason, bannedBy: 'System', banId }).catch(() => {});
    res.json({ success: true, banId });
});

// === ADMIN API ===
app.get('/api/admin/stats', adminAuth, async (req, res) => { try { const s = await db.getStats(); res.json({ success: true, stats: s, sessions: SESSIONS.size, ts: new Date().toISOString() }); } catch (e) { res.status(500).json({ success: false, error: 'Failed' }); } });
app.get('/api/admin/logs', adminAuth, async (req, res) => { const l = await db.getLogs(50); res.json({ success: true, logs: l }); });
app.post('/api/admin/logs/clear', adminAuth, async (req, res) => { await db.clearLogs(); res.json({ success: true }); });
app.get('/api/admin/bans', adminAuth, async (req, res) => { const b = await db.getAllBans(); res.json({ success: true, bans: b }); });
app.post('/api/admin/bans', adminAuth, async (req, res) => { const { hwid, ip, playerId, reason } = req.body; if (!hwid && !ip && !playerId) return res.status(400).json({ success: false, error: 'Required' }); const banId = crypto.randomBytes(8).toString('hex').toUpperCase(); const data = { reason: reason || 'Manual', banId, ts: new Date().toISOString() }; if (hwid) await db.addBan(hwid, { hwid, ...data }); if (playerId) await db.addBan(String(playerId), { playerId, ...data }); if (ip) await db.addBan(ip, { ip, ...data }); webhook.ban({ userId: playerId, hwid, ip, reason, bannedBy: 'Admin', banId }).catch(() => {}); res.json({ success: true, banId }); });
app.delete('/api/admin/bans/:id', adminAuth, async (req, res) => { const r = await db.removeBanById(req.params.id); res.json({ success: r }); });
app.post('/api/admin/bans/clear', adminAuth, async (req, res) => { const count = await db.clearBans(); res.json({ success: true, cleared: count }); });
app.post('/api/admin/cache/clear', adminAuth, async (req, res) => { await db.setCachedScript(null); res.json({ success: true }); });
app.post('/api/admin/sessions/clear', adminAuth, async (req, res) => { const count = SESSIONS.size; SESSIONS.clear(); res.json({ success: true, cleared: count }); });
app.get('/api/admin/whitelist', adminAuth, async (req, res) => { res.json({ success: true, whitelist: { userIds: [...(config.WHITELIST_USER_IDS || []), ...Array.from(dynamicWhitelist.userIds)], hwids: [...(config.WHITELIST_HWIDS || []), ...Array.from(dynamicWhitelist.hwids)], ips: [...(config.WHITELIST_IPS || []), ...Array.from(dynamicWhitelist.ips)], owners: config.OWNER_USER_IDS || [] } }); });
app.post('/api/admin/whitelist', adminAuth, async (req, res) => { const { type, value } = req.body; if (!type || !value) return res.status(400).json({ success: false, error: 'Missing fields' }); if (type === 'userId') dynamicWhitelist.userIds.add(parseInt(value)); else if (type === 'hwid') dynamicWhitelist.hwids.add(String(value)); else if (type === 'ip') dynamicWhitelist.ips.add(String(value)); else return res.status(400).json({ success: false, error: 'Invalid type' }); res.json({ success: true, msg: `Added ${type}: ${value}` }); });
app.post('/api/admin/whitelist/remove', adminAuth, async (req, res) => { const { type, value } = req.body; if (!type || !value) return res.status(400).json({ success: false, error: 'Missing fields' }); if (type === 'userId') dynamicWhitelist.userIds.delete(parseInt(value)); else if (type === 'hwid') dynamicWhitelist.hwids.delete(String(value)); else if (type === 'ip') dynamicWhitelist.ips.delete(String(value)); res.json({ success: true, msg: `Removed ${type}: ${value}` }); });
app.get('/api/admin/suspended', adminAuth, async (req, res) => { const a = []; suspendedUsers.hwids.forEach((v, k) => a.push({ type: 'hwid', value: k, ...v })); suspendedUsers.userIds.forEach((v, k) => a.push({ type: 'userId', value: k, ...v })); suspendedUsers.sessions.forEach((v, k) => a.push({ type: 'session', value: k, ...v })); res.json({ success: true, suspended: a }); });
app.post('/api/admin/suspend', adminAuth, async (req, res) => { const { type, value, reason, duration } = req.body; if (!type || !value) return res.status(400).json({ success: false, error: 'Missing type or value' }); if (!['hwid', 'userId', 'session'].includes(type)) return res.status(400).json({ success: false, error: 'Invalid type' }); const d = { reason: reason || 'Suspended by admin', suspendedAt: new Date().toISOString(), expiresAt: duration ? new Date(Date.now() + parseInt(duration) * 1000).toISOString() : null }; if (type === 'hwid') suspendedUsers.hwids.set(String(value), d); else if (type === 'userId') suspendedUsers.userIds.set(String(value), d); else if (type === 'session') suspendedUsers.sessions.set(String(value), d); await db.addSuspend(type, String(value), d); res.json({ success: true, msg: `Suspended ${type}: ${value}${duration ? ' for ' + duration + 's' : ' permanently'}` }); });
app.post('/api/admin/unsuspend', adminAuth, async (req, res) => { const { type, value } = req.body; if (!type || !value) return res.status(400).json({ success: false, error: 'Missing fields' }); if (type === 'hwid') suspendedUsers.hwids.delete(String(value)); else if (type === 'userId') suspendedUsers.userIds.delete(String(value)); else if (type === 'session') suspendedUsers.sessions.delete(String(value)); await db.removeSuspend(type, String(value)); res.json({ success: true, msg: `Unsuspended ${type}: ${value}` }); });
app.post('/api/admin/kill-session', adminAuth, async (req, res) => { const { sessionId, reason } = req.body; if (!sessionId) return res.status(400).json({ success: false, error: 'Missing sessionId' }); const session = SESSIONS.get(sessionId); if (!session) return res.status(404).json({ success: false, error: 'Session not found' }); await suspendUser('session', sessionId, { reason: reason || 'Killed by admin', userId: session.userId, hwid: session.hwid, ip: session.ip }); res.json({ success: true, msg: 'Session will be terminated on next heartbeat' }); });
app.get('/api/admin/sessions', adminAuth, async (req, res) => { const arr = []; SESSIONS.forEach((v, k) => arr.push({ sessionId: k, ...v, age: Math.floor((Date.now() - v.created) / 1000) })); res.json({ success: true, sessions: arr.sort((a, b) => b.created - a.created) }); });

app.use('*', (req, res) => { const ct = getClientType(req); if (ct === 'browser') return res.status(404).type('html').send(TRAP_HTML); res.status(403).type('text/plain').send(genFakeScript()); });

const PORT = process.env.PORT || config.PORT || 3000;
loadSuspendedFromDB().then(() => { webhook.serverStart().catch(() => {}); app.listen(PORT, '0.0.0.0', () => { console.log(`\n🛡️ Script Shield v2.1 running on port ${PORT}\n📍 Admin: http://localhost:${PORT}${adminPath}\n📦 Loader: http://localhost:${PORT}/loader\n`); }); });
