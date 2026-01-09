/* ============================================
   API - HTTP Request Handler
   ============================================ */

const API = {
    // Get stored admin key
    getKey() {
        return localStorage.getItem(CONFIG.STORAGE.ADMIN_KEY) || '';
    },
    
    // Set admin key
    setKey(key) {
        localStorage.setItem(CONFIG.STORAGE.ADMIN_KEY, key);
    },
    
    // Clear admin key
    clearKey() {
        localStorage.removeItem(CONFIG.STORAGE.ADMIN_KEY);
    },
    
    // Base fetch wrapper
    async request(endpoint, options = {}) {
        const url = CONFIG.API_BASE + endpoint;
        const key = this.getKey();
        
        const defaultHeaders = {
            'Content-Type': 'application/json',
            'x-admin-key': key,
        };
        
        const config = {
            ...options,
            headers: {
                ...defaultHeaders,
                ...options.headers,
            },
        };
        
        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            // Handle unauthorized
            if (response.status === 403) {
                if (data.error === 'Unauthorized') {
                    Auth.logout();
                    return { success: false, error: 'Session expired' };
                }
            }
            
            return data;
        } catch (error) {
            console.error('API Error:', error);
            return { 
                success: false, 
                error: 'Network error. Please try again.' 
            };
        }
    },
    
    // GET request
    async get(endpoint, params = {}) {
        const query = new URLSearchParams(params).toString();
        const url = query ? `${endpoint}?${query}` : endpoint;
        return this.request(url, { method: 'GET' });
    },
    
    // POST request
    async post(endpoint, body = {}) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(body),
        });
    },
    
    // DELETE request
    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    },
    
    // ===== Specific API Methods =====
    
    // Stats
    async getStats() {
        return this.get(CONFIG.ENDPOINTS.STATS);
    },
    
    // Bans
    async getBans() {
        return this.get(CONFIG.ENDPOINTS.BANS);
    },
    
    async addBan(data) {
        return this.post(CONFIG.ENDPOINTS.BANS, data);
    },
    
    async removeBan(banId) {
        return this.delete(`${CONFIG.ENDPOINTS.BANS}/${banId}`);
    },
    
    async clearAllBans() {
        return this.post(CONFIG.ENDPOINTS.BAN_CLEAR);
    },
    
    // Logs
    async getLogs(limit = 50) {
        return this.get(CONFIG.ENDPOINTS.LOGS, { limit });
    },
    
    // Cache & Sessions
    async clearCache() {
        return this.post(CONFIG.ENDPOINTS.CACHE_CLEAR);
    },
    
    async clearSessions() {
        return this.post(CONFIG.ENDPOINTS.SESSIONS_CLEAR);
    },
};
