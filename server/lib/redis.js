/* ============================================
   REDIS/MEMORY DATABASE HANDLER
   Supports Redis for production, Memory for development
   ============================================ */

const config = require('../config');

let redis = null;
let useRedis = false;
let isConnecting = false;

// ==================== MEMORY STORAGE ====================
const memoryStore = {
    bans: new Map(),
    logs: [],
    challenges: new Map(),
    cache: new Map(),
    stats: { 
        success: 0, 
        challenges: 0, 
        bans: 0 
    }
};

// ==================== INITIALIZATION ====================
async function initRedis() {
    if (isConnecting) return;
    isConnecting = true;
    
    if (config.REDIS_URL) {
        try {
            const Redis = require('ioredis');
            
            redis = new Redis(config.REDIS_URL, {
                maxRetriesPerRequest: 3,
                retryDelayOnFailover: 100,
                lazyConnect: true,
                connectTimeout: 10000,
                commandTimeout: 5000,
            });
            
            // Event handlers
            redis.on('connect', () => {
                console.log('✅ Redis connected successfully');
                useRedis = true;
            });
            
            redis.on('error', (err) => {
                console.error('❌ Redis error:', err.message);
            });
            
            redis.on('close', () => {
                console.log('⚠️ Redis connection closed');
                useRedis = false;
            });
            
            // Test connection
            await redis.ping();
            useRedis = true;
            
        } catch (err) {
            console.log('⚠️ Redis connection failed, using memory storage');
            console.log('   Error:', err.message);
            useRedis = false;
        }
    } else {
        console.log('ℹ️ No REDIS_URL provided, using memory storage');
        console.log('   ⚠️ Data will be lost on server restart!');
    }
    
    isConnecting = false;
}

// Initialize on module load
initRedis();

// ==================== BANS ====================
async function addBan(key, data) {
    memoryStore.stats.bans++;
    
    if (useRedis) {
        try {
            await redis.hset('bans', key, JSON.stringify(data));
            await redis.incr('stats:bans');
            return true;
        } catch (e) {
            console.error('Redis addBan error:', e.message);
        }
    }
    
    memoryStore.bans.set(key, data);
    return true;
}

async function removeBan(key) {
    if (useRedis) {
        try {
            await redis.hdel('bans', key);
            return true;
        } catch (e) {
            console.error('Redis removeBan error:', e.message);
        }
    }
    
    memoryStore.bans.delete(key);
    return true;
}

async function removeBanById(banId) {
    if (useRedis) {
        try {
            const all = await redis.hgetall('bans');
            for (const [key, value] of Object.entries(all)) {
                try {
                    const parsed = JSON.parse(value);
                    if (parsed.banId === banId) {
                        await redis.hdel('bans', key);
                        return true;
                    }
                } catch {}
            }
            return false;
        } catch (e) {
            console.error('Redis removeBanById error:', e.message);
        }
    }
    
    for (const [key, value] of memoryStore.bans) {
        if (value.banId === banId) {
            memoryStore.bans.delete(key);
            return true;
        }
    }
    return false;
}

async function isBanned(hwid, ip, playerId) {
    const keysToCheck = [
        hwid, 
        ip, 
        playerId ? String(playerId) : null
    ].filter(Boolean);
    
    if (keysToCheck.length === 0) {
        return { blocked: false };
    }
    
    if (useRedis) {
        try {
            for (const key of keysToCheck) {
                const data = await redis.hget('bans', key);
                if (data) {
                    try {
                        const parsed = JSON.parse(data);
                        return { 
                            blocked: true, 
                            reason: parsed.reason || 'Banned',
                            banId: parsed.banId
                        };
                    } catch {}
                }
            }
            return { blocked: false };
        } catch (e) {
            console.error('Redis isBanned error:', e.message);
        }
    }
    
    for (const key of keysToCheck) {
        if (memoryStore.bans.has(key)) {
            const data = memoryStore.bans.get(key);
            return { 
                blocked: true, 
                reason: data.reason || 'Banned',
                banId: data.banId
            };
        }
    }
    return { blocked: false };
}

async function getAllBans() {
    if (useRedis) {
        try {
            const all = await redis.hgetall('bans');
            return Object.values(all)
                .map(v => {
                    try { return JSON.parse(v); } 
                    catch { return null; }
                })
                .filter(Boolean)
                .sort((a, b) => new Date(b.ts) - new Date(a.ts));
        } catch (e) {
            console.error('Redis getAllBans error:', e.message);
        }
    }
    
    return Array.from(memoryStore.bans.values())
        .sort((a, b) => new Date(b.ts) - new Date(a.ts));
}

async function clearBans() {
    if (useRedis) {
        try {
            const all = await redis.hgetall('bans');
            const count = Object.keys(all).length;
            if (count > 0) {
                await redis.del('bans');
            }
            return count;
        } catch (e) {
            console.error('Redis clearBans error:', e.message);
        }
    }
    
    const count = memoryStore.bans.size;
    memoryStore.bans.clear();
    return count;
}

// ==================== CHALLENGES ====================
async function setChallenge(id, data, ttl = 120) {
    memoryStore.stats.challenges++;
    
    if (useRedis) {
        try {
            await redis.setex(`challenge:${id}`, ttl, JSON.stringify(data));
            await redis.incr('stats:challenges');
            return true;
        } catch (e) {
            console.error('Redis setChallenge error:', e.message);
        }
    }
    
    memoryStore.challenges.set(id, {
        ...data,
        expiresAt: Date.now() + (ttl * 1000)
    });
    return true;
}

async function getChallenge(id) {
    if (useRedis) {
        try {
            const data = await redis.get(`challenge:${id}`);
            if (data) {
                try { return JSON.parse(data); }
                catch { return null; }
            }
            return null;
        } catch (e) {
            console.error('Redis getChallenge error:', e.message);
        }
    }
    
    const data = memoryStore.challenges.get(id);
    if (data && data.expiresAt > Date.now()) {
        return data;
    }
    memoryStore.challenges.delete(id);
    return null;
}

async function deleteChallenge(id) {
    if (useRedis) {
        try {
            await redis.del(`challenge:${id}`);
            return true;
        } catch (e) {
            console.error('Redis deleteChallenge error:', e.message);
        }
    }
    
    memoryStore.challenges.delete(id);
    return true;
}

// ==================== LOGS ====================
async function addLog(log) {
    if (useRedis) {
        try {
            await redis.lpush('logs', JSON.stringify(log));
            await redis.ltrim('logs', 0, 999); // Keep last 1000
            
            if (log.success) {
                await redis.incr('stats:success');
            }
            return true;
        } catch (e) {
            console.error('Redis addLog error:', e.message);
        }
    }
    
    memoryStore.logs.unshift(log);
    if (memoryStore.logs.length > 1000) {
        memoryStore.logs = memoryStore.logs.slice(0, 1000);
    }
    if (log.success) {
        memoryStore.stats.success++;
    }
    return true;
}

async function getLogs(limit = 50) {
    const safeLimit = Math.min(Math.max(1, limit), 500);
    
    if (useRedis) {
        try {
            const logs = await redis.lrange('logs', 0, safeLimit - 1);
            return logs
                .map(l => {
                    try { return JSON.parse(l); }
                    catch { return null; }
                })
                .filter(Boolean);
        } catch (e) {
            console.error('Redis getLogs error:', e.message);
        }
    }
    
    return memoryStore.logs.slice(0, safeLimit);
}

// ==================== CACHE ====================
async function getCachedScript() {
    if (useRedis) {
        try {
            return await redis.get('cached_script');
        } catch (e) {
            console.error('Redis getCachedScript error:', e.message);
        }
    }
    
    const cached = memoryStore.cache.get('script');
    if (cached && cached.expiresAt > Date.now()) {
        return cached.data;
    }
    memoryStore.cache.delete('script');
    return null;
}

async function setCachedScript(script, ttl = 300) {
    if (!script) {
        // Clear cache
        if (useRedis) {
            try { 
                await redis.del('cached_script'); 
            } catch {}
        }
        memoryStore.cache.delete('script');
        return true;
    }
    
    if (useRedis) {
        try {
            await redis.setex('cached_script', ttl, script);
            return true;
        } catch (e) {
            console.error('Redis setCachedScript error:', e.message);
        }
    }
    
    memoryStore.cache.set('script', {
        data: script,
        expiresAt: Date.now() + (ttl * 1000)
    });
    return true;
}

// ==================== STATS ====================
async function getStats() {
    if (useRedis) {
        try {
            const [success, challenges, bansCount] = await Promise.all([
                redis.get('stats:success'),
                redis.get('stats:challenges'),
                redis.hlen('bans')
            ]);
            
            return {
                success: parseInt(success) || 0,
                challenges: parseInt(challenges) || 0,
                bans: parseInt(bansCount) || 0
            };
        } catch (e) {
            console.error('Redis getStats error:', e.message);
        }
    }
    
    return {
        success: memoryStore.stats.success,
        challenges: memoryStore.stats.challenges,
        bans: memoryStore.bans.size
    };
}

// ==================== CLEANUP ====================
// Clean expired challenges (memory only - Redis handles TTL automatically)
setInterval(() => {
    if (!useRedis) {
        const now = Date.now();
        for (const [id, data] of memoryStore.challenges) {
            if (data.expiresAt && data.expiresAt < now) {
                memoryStore.challenges.delete(id);
            }
        }
        
        // Also clean expired cache
        for (const [key, data] of memoryStore.cache) {
            if (data.expiresAt && data.expiresAt < now) {
                memoryStore.cache.delete(key);
            }
        }
    }
}, 60000); // Every minute

// ==================== EXPORTS ====================
module.exports = {
    // Bans
    addBan,
    removeBan,
    removeBanById,
    isBanned,
    getAllBans,
    clearBans,
    
    // Challenges
    setChallenge,
    getChallenge,
    deleteChallenge,
    
    // Logs
    addLog,
    getLogs,
    
    // Cache
    getCachedScript,
    setCachedScript,
    
    // Stats
    getStats,
    
    // Utils
    isRedisConnected: () => useRedis,
};
