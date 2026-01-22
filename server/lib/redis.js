const crypto = require('crypto');
let redis = null;

// Memory store jika Redis tidak ada
let memoryStore = {
    bans: {},
    challenges: {},
    logs: [],
    suspends: {},
    cache: {}
};

const REDIS_URL = process.env.REDIS_URL || process.env.KV_URL || null;

async function initRedis() {
    if (REDIS_URL) {
        try {
            const { createClient } = require('redis');
            redis = createClient({ url: REDIS_URL });
            redis.on('error', (err) => console.error('Redis Client Error', err));
            await redis.connect();
            console.log('✅ Redis Connected Successfully');
            return true;
        } catch (e) {
            console.error('❌ Redis Connection Failed:', e.message);
            redis = null;
        }
    } else {
        console.log('⚠️ WARNING: Redis URL not found. Using MEMORY storage. Data will be lost on restart & Bot will NOT sync with Server.');
    }
    return false;
}

function isRedisConnected() { return redis && redis.isOpen; }

// === BAN SYSTEM FIX ===

async function addBan(key, data) {
    // Pastikan banId ada
    const banId = data.banId || crypto.randomBytes(8).toString('hex').toUpperCase();
    const banData = { ...data, banId, key, ts: new Date().toISOString() };
    
    if (redis) {
        // Simpan dengan key banId agar mudah dihapus
        await redis.hSet('shield:bans', banId, JSON.stringify(banData));
    } else {
        memoryStore.bans[banId] = banData;
    }
    return banId;
}

async function getAllBans() {
    if (redis) {
        const all = await redis.hGetAll('shield:bans');
        return Object.values(all).map(v => {
            try { return JSON.parse(v) } catch { return null }
        }).filter(Boolean);
    }
    return Object.values(memoryStore.bans);
}

async function removeBanById(banId) {
    if (!banId) return false;
    const id = String(banId).toUpperCase(); // Normalisasi ID

    if (redis) {
        // Cek langsung by Ban ID
        const exists = await redis.hExists('shield:bans', id);
        if (exists) {
            await redis.hDel('shield:bans', id);
            return true;
        }
        
        // Fallback: Cari manual jika format lama (disimpan by HWID/PlayerID)
        const all = await redis.hGetAll('shield:bans');
        for (const [key, value] of Object.entries(all)) {
            try {
                const data = JSON.parse(value);
                // Jika HWID atau PlayerID cocok dengan input, atau banId cocok
                if (data.banId === id || key === id || data.hwid === banId || data.playerId === banId) {
                    await redis.hDel('shield:bans', key);
                    return true;
                }
            } catch {}
        }
        return false;
    } 
    
    // Memory Store Logic
    if (memoryStore.bans[id]) {
        delete memoryStore.bans[id];
        return true;
    }
    // Search in memory values
    for (const [key, val] of Object.entries(memoryStore.bans)) {
        if (val.banId === id || val.hwid === banId || val.playerId === banId) {
            delete memoryStore.bans[key];
            return true;
        }
    }
    return false;
}

async function clearBans() {
    if (redis) {
        const len = await redis.hLen('shield:bans');
        if (len > 0) await redis.del('shield:bans');
        return len;
    }
    const len = Object.keys(memoryStore.bans).length;
    memoryStore.bans = {};
    return len;
}

async function isBanned(hwid, ip, userId) {
    const bans = await getAllBans();
    for (const ban of bans) {
        if (hwid && ban.hwid && String(ban.hwid).toLowerCase() === String(hwid).toLowerCase()) return { blocked: true, reason: ban.reason || 'HWID Ban', banId: ban.banId };
        if (userId && ban.playerId && String(ban.playerId) === String(userId)) return { blocked: true, reason: ban.reason || 'User Ban', banId: ban.banId };
        if (ip && ban.ip && ban.ip === ip) return { blocked: true, reason: ban.reason || 'IP Ban', banId: ban.banId };
    }
    return { blocked: false };
}

async function getBanCount() {
    if (redis) { try { return await redis.hLen('shield:bans') } catch { return 0 } }
    return Object.keys(memoryStore.bans).length;
}

// === CHALLENGE & LOGS ===

async function setChallenge(id, data, ttl = 120) {
    if (redis) await redis.setEx(`shield:challenge:${id}`, ttl, JSON.stringify(data));
    else memoryStore.challenges[id] = { ...data, expiresAt: Date.now() + ttl * 1000 };
}

async function getChallenge(id) {
    if (redis) {
        const d = await redis.get(`shield:challenge:${id}`);
        return d ? JSON.parse(d) : null;
    }
    const c = memoryStore.challenges[id];
    if (c && c.expiresAt > Date.now()) return c;
    if (c) delete memoryStore.challenges[id];
    return null;
}

async function deleteChallenge(id) {
    if (redis) await redis.del(`shield:challenge:${id}`);
    else delete memoryStore.challenges[id];
}

async function addLog(log) {
    if (redis) {
        await redis.lPush('shield:logs', JSON.stringify(log));
        await redis.lTrim('shield:logs', 0, 499);
    } else {
        memoryStore.logs.unshift(log);
        if (memoryStore.logs.length > 500) memoryStore.logs.pop();
    }
}

async function getLogs(limit = 50) {
    if (redis) {
        const logs = await redis.lRange('shield:logs', 0, limit - 1);
        return logs.map(l => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean);
    }
    return memoryStore.logs.slice(0, limit);
}

async function clearLogs() {
    if (redis) await redis.del('shield:logs');
    else memoryStore.logs = [];
}

// === CACHE & SUSPEND ===

async function setCachedScript(script) {
    if (redis) {
        if (script) await redis.setEx('shield:script', 3600, script);
        else await redis.del('shield:script');
    } else {
        if (script) memoryStore.cache.script = { data: script, ts: Date.now() };
        else delete memoryStore.cache.script;
    }
}

async function getCachedScript() {
    if (redis) return await redis.get('shield:script');
    const c = memoryStore.cache.script;
    if (c && Date.now() - c.ts < 3600000) return c.data;
    return null;
}

async function addSuspend(type, value, data) {
    if(redis) await redis.hSet('shield:suspends', `${type}:${value}`, JSON.stringify(data));
    else memoryStore.suspends[`${type}:${value}`] = data;
}

async function removeSuspend(type, value) {
    if(redis) await redis.hDel('shield:suspends', `${type}:${value}`);
    else delete memoryStore.suspends[`${type}:${value}`];
}

async function getAllSuspends() {
    if(redis) {
        const all = await redis.hGetAll('shield:suspends');
        return Object.values(all).map(v => JSON.parse(v));
    }
    return Object.values(memoryStore.suspends);
}

async function getStats() {
    return {
        bans: await getBanCount(),
        logs: redis ? await redis.lLen('shield:logs') : memoryStore.logs.length,
        redis: isRedisConnected()
    };
}

initRedis();

module.exports = {
    isRedisConnected,
    addBan, getAllBans, removeBanById, clearBans, isBanned, getBanCount,
    setChallenge, getChallenge, deleteChallenge,
    addLog, getLogs, clearLogs,
    addSuspend, removeSuspend, getAllSuspends,
    setCachedScript, getCachedScript, getStats
};
