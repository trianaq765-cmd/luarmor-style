/* ============================================
   API - HTTP Request Handler (FIXED)
   ============================================ */

const API = {
    // Request timeout (ms)
    TIMEOUT: 10000,
    
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
    
    // Fetch with timeout
    async fetchWithTimeout(url, options = {}) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.TIMEOUT);
        
        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error('Request timeout - server tidak merespons');
            }
            throw error;
        }
    },
    
    // Base fetch wrapper
    async request(endpoint, options = {}) {
        const url = CONFIG.API_BASE + endpoint;
        const key = this.getKey();
        
        const defaultHeaders = {
            'Content-Type': 'application/json',
        };
        
        // Only add admin key if exists
        if (key) {
            defaultHeaders['x-admin-key'] = key;
        }
        
        const config = {
            ...options,
            headers: {
                ...defaultHeaders,
                ...options.headers,
            },
        };
        
        console.log(`[API] ${options.method || 'GET'} ${endpoint}`);
        
        try {
            const response = await this.fetchWithTimeout(url, config);
            
            // Try to parse JSON
            let data;
            const contentType = response.headers.get('content-type');
            
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                const text = await response.text();
                console.warn('[API] Non-JSON response:', text.substring(0, 100));
                data = { success: false, error: 'Invalid server response' };
            }
            
            console.log(`[API] Response:`, data);
            
            // Handle HTTP errors
            if (!response.ok) {
                if (response.status === 403) {
                    if (data.error === 'Unauthorized') {
                        return { 
                            success: false, 
                            error: 'Invalid admin key',
                            code: 'UNAUTHORIZED'
                        };
                    }
                }
                return { 
                    success: false, 
                    error: data.error || `HTTP Error ${response.status}`,
                    code: 'HTTP_ERROR'
                };
            }
            
            return data;
            
        } catch (error) {
            console.error('[API] Error:', error);
            
            // Network errors
            if (error.message.includes('timeout')) {
                return { 
                    success: false, 
                    error: 'Server timeout - coba lagi',
                    code: 'TIMEOUT'
                };
            }
            
            if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
                return { 
                    success: false, 
                    error: 'Tidak dapat terhubung ke server',
                    code: 'NETWORK_ERROR'
                };
            }
            
            return { 
                success: false, 
                error: error.message || 'Unknown error',
                code: 'UNKNOWN'
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
    
    // Verify admin key (quick check)
    async verifyKey(key) {
        const originalKey = this.getKey();
        this.setKey(key);
        
        const result = await this.get(CONFIG.ENDPOINTS.STATS);
        
        if (!result.success) {
            // Restore original key if failed
            if (originalKey) {
                this.setKey(originalKey);
            } else {
                this.clearKey();
            }
        }
        
        return result;
    },
    
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
