// ============================================================
// 💾 DATABASE & CACHE MODULE
// ============================================================

const NodeCache = require('node-cache');
const config = require('./config');

// Script Cache
const scriptCache = new NodeCache({ 
    stdTTL: config.CACHE?.TTL || 300, 
    checkperiod: config.CACHE?.CHECK_PERIOD || 60 
});

// Blocked Devices Storage
const blockedDevices = {
    devices: new Map(),
    
    addBlock(data) {
        const { hwid, ip, playerId, playerName, reason, toolsDetected, banId, timestamp } = data;
        
        const blockEntry = {
            hwid,
            ip,
            playerId,
            playerName,
            reason,
            toolsDetected,
            banId,
            timestamp,
            blockedAt: Date.now()
        };
        
        // Store by multiple keys for faster lookup
        if (hwid) this.devices.set(`hwid:${hwid}`, blockEntry);
        if (ip) this.devices.set(`ip:${ip}`, blockEntry);
        if (playerId) this.devices.set(`pid:${playerId}`, blockEntry);
        if (banId) this.devices.set(`ban:${banId}`, blockEntry);
    },
    
    isBlocked(hwid, ip, playerId) {
        let entry = null;
        
        if (hwid && this.devices.has(`hwid:${hwid}`)) {
            entry = this.devices.get(`hwid:${hwid}`);
        } else if (playerId && this.devices.has(`pid:${playerId}`)) {
            entry = this.devices.get(`pid:${playerId}`);
        } else if (ip && this.devices.has(`ip:${ip}`)) {
            entry = this.devices.get(`ip:${ip}`);
        }
        
        if (entry) {
            return {
                blocked: true,
                reason: entry.reason,
                banId: entry.banId,
                blockedAt: entry.timestamp
            };
        }
        
        return { blocked: false };
    },
    
    removeByBanId(banId) {
        const entry = this.devices.get(`ban:${banId}`);
        if (entry) {
            if (entry.hwid) this.devices.delete(`hwid:${entry.hwid}`);
            if (entry.ip) this.devices.delete(`ip:${entry.ip}`);
            if (entry.playerId) this.devices.delete(`pid:${entry.playerId}`);
            this.devices.delete(`ban:${banId}`);
            return true;
        }
        return false;
    },
    
    getAll() {
        const bans = [];
        const seen = new Set();
        
        this.devices.forEach((entry, key) => {
            if (key.startsWith('ban:') && !seen.has(entry.banId)) {
                seen.add(entry.banId);
                bans.push(entry);
            }
        });
        
        return bans;
    },
    
    count() {
        const seen = new Set();
        this.devices.forEach((entry) => {
            if (entry.banId) seen.add(entry.banId);
        });
        return seen.size;
    }
};

// Logs Database
const db = {
    logs: [],
    stats: {
        totalRequests: 0,
        successfulRequests: 0,
        blockedRequests: 0,
        browserBlocked: 0,
        protectedServed: 0,
        devicesBanned: 0
    },
    
    addLog(log) {
        this.logs.unshift({
            ...log,
            timestamp: log.timestamp || new Date().toISOString()
        });
        
        if (this.logs.length > 1000) {
            this.logs = this.logs.slice(0, 1000);
        }
        
        this.stats.totalRequests++;
        if (log.success) {
            this.stats.successfulRequests++;
        }
        if (log.action === 'BROWSER_BLOCKED') {
            this.stats.browserBlocked++;
        }
        if (log.action === 'SCRIPT_SERVED') {
            this.stats.protectedServed++;
        }
        if (log.action === 'DEVICE_BANNED') {
            this.stats.devicesBanned++;
        }
    },
    
    getLogs(limit = 50) {
        return this.logs.slice(0, limit);
    },
    
    getStats() {
        return {
            ...this.stats,
            cacheHits: scriptCache.getStats().hits,
            cacheMisses: scriptCache.getStats().misses
        };
    }
};

module.exports = { db, scriptCache, blockedDevices };
