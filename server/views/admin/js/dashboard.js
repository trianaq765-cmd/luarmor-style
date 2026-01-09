/* ============================================
   DASHBOARD - Stats & Overview
   ============================================ */

const Dashboard = {
    refreshInterval: null,
    stats: {
        sessions: 0,
        success: 0,
        challenges: 0,
        bans: 0,
    },
    
    // Initialize dashboard
    async init() {
        await this.loadStats();
        this.startAutoRefresh();
    },
    
    // Load stats from API
    async loadStats() {
        const result = await API.getStats();
        
        if (result.success) {
            this.stats = {
                sessions: result.sessions || 0,
                success: result.stats?.success || 0,
                challenges: result.stats?.challenges || 0,
                bans: result.stats?.bans || 0,
            };
            this.renderStats();
        } else {
            Utils.toast('Failed to load stats', 'error');
        }
    },
    
    // Render stats cards
    renderStats() {
        const elements = {
            sessions: document.getElementById('statSessions'),
            success: document.getElementById('statSuccess'),
            challenges: document.getElementById('statChallenges'),
            bans: document.getElementById('statBans'),
        };
        
        // Animate number changes
        this.animateNumber(elements.sessions, this.stats.sessions);
        this.animateNumber(elements.success, this.stats.success);
        this.animateNumber(elements.challenges, this.stats.challenges);
        this.animateNumber(elements.bans, this.stats.bans);
    },
    
    // Animate number counting
    animateNumber(element, target) {
        if (!element) return;
        
        const current = parseInt(element.textContent.replace(/,/g, '')) || 0;
        const diff = target - current;
        const duration = 500;
        const steps = 20;
        const increment = diff / steps;
        let step = 0;
        
        const timer = setInterval(() => {
            step++;
            const value = Math.round(current + (increment * step));
            element.textContent = Utils.formatNumber(value);
            
            if (step >= steps) {
                clearInterval(timer);
                element.textContent = Utils.formatNumber(target);
            }
        }, duration / steps);
    },
    
    // Start auto refresh
    startAutoRefresh() {
        this.stopAutoRefresh();
        this.refreshInterval = setInterval(() => {
            this.loadStats();
        }, CONFIG.INTERVALS.STATS);
    },
    
    // Stop auto refresh
    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    },
    
    // Manual refresh
    async refresh() {
        const btn = document.getElementById('refreshStatsBtn');
        if (btn) {
            btn.classList.add('animate-spin');
            btn.disabled = true;
        }
        
        await this.loadStats();
        
        if (btn) {
            setTimeout(() => {
                btn.classList.remove('animate-spin');
                btn.disabled = false;
            }, 500);
        }
        
        Utils.toast('Stats refreshed', 'success');
    },
    
    // Render dashboard page
    render() {
        return `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Dashboard</h1>
                    <p class="page-subtitle">Overview of your script protection system</p>
                </div>
                <button class="btn btn-secondary" id="refreshStatsBtn" onclick="Dashboard.refresh()">
                    <span class="btn-icon">↻</span>
                    Refresh
                </button>
            </div>
            
            <div class="stats-grid stagger-children">
                <div class="stat-card animate-fadeInUp">
                    <div class="stat-card-header">
                        <div class="stat-card-icon blue">👥</div>
                        <div class="stat-card-trend up">
                            <span>↑</span>
                            <span>Active</span>
                        </div>
                    </div>
                    <div class="stat-card-value" id="statSessions">0</div>
                    <div class="stat-card-label">Active Sessions</div>
                    <div class="stat-card-progress">
                        <div class="stat-card-progress-bar" style="width: 75%"></div>
                    </div>
                </div>
                
                <div class="stat-card animate-fadeInUp">
                    <div class="stat-card-header">
                        <div class="stat-card-icon green">✓</div>
                    </div>
                    <div class="stat-card-value" id="statSuccess">0</div>
                    <div class="stat-card-label">Successful Loads</div>
                    <div class="stat-card-progress">
                        <div class="stat-card-progress-bar" style="width: 85%"></div>
                    </div>
                </div>
                
                <div class="stat-card animate-fadeInUp">
                    <div class="stat-card-header">
                        <div class="stat-card-icon orange">🔐</div>
                    </div>
                    <div class="stat-card-value" id="statChallenges">0</div>
                    <div class="stat-card-label">Challenges Issued</div>
                    <div class="stat-card-progress">
                        <div class="stat-card-progress-bar" style="width: 60%"></div>
                    </div>
                </div>
                
                <div class="stat-card animate-fadeInUp">
                    <div class="stat-card-header">
                        <div class="stat-card-icon red">🚫</div>
                    </div>
                    <div class="stat-card-value" id="statBans">0</div>
                    <div class="stat-card-label">Total Bans</div>
                    <div class="stat-card-progress">
                        <div class="stat-card-progress-bar" style="width: 20%"></div>
                    </div>
                </div>
            </div>
            
            <div class="content-grid two-cols">
                <div class="card animate-fadeInUp">
                    <div class="card-header">
                        <h3 class="card-title">
                            <span class="card-title-icon">📋</span>
                            Recent Activity
                        </h3>
                        <a href="#" onclick="App.navigate('logs'); return false;" class="btn btn-ghost btn-sm">
                            View All →
                        </a>
                    </div>
                    <div class="card-body" id="recentActivity">
                        <div class="empty-state">
                            <div class="spinner"></div>
                            <p class="text-muted" style="margin-top: 16px;">Loading activity...</p>
                        </div>
                    </div>
                </div>
                
                <div class="card animate-fadeInUp">
                    <div class="card-header">
                        <h3 class="card-title">
                            <span class="card-title-icon">⚡</span>
                            Quick Actions
                        </h3>
                    </div>
                    <div class="card-body">
                        <div class="quick-actions">
                            <button class="btn btn-secondary btn-block" onclick="App.navigate('bans')">
                                🚫 Manage Bans
                            </button>
                            <button class="btn btn-secondary btn-block" onclick="Dashboard.clearCache()">
                                🗑️ Clear Script Cache
                            </button>
                            <button class="btn btn-secondary btn-block" onclick="Dashboard.clearSessions()">
                                🔄 Clear Sessions
                            </button>
                            <button class="btn btn-secondary btn-block" onclick="Dashboard.copyLoader()">
                                📋 Copy Loader Script
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },
    
    // Clear cache action
    async clearCache() {
        const confirmed = await Utils.confirm(
            'This will clear the cached script. Next request will fetch fresh script.',
            'Clear Cache?'
        );
        
        if (!confirmed) return;
        
        const result = await API.clearCache();
        if (result.success) {
            Utils.toast('Script cache cleared', 'success');
        } else {
            Utils.toast(result.error || 'Failed to clear cache', 'error');
        }
    },
    
    // Clear sessions action
    async clearSessions() {
        const confirmed = await Utils.confirm(
            'This will terminate all active sessions. Users will need to re-authenticate.',
            'Clear Sessions?'
        );
        
        if (!confirmed) return;
        
        const result = await API.clearSessions();
        if (result.success) {
            Utils.toast(`Cleared ${result.cleared || 0} sessions`, 'success');
            this.loadStats();
        } else {
            Utils.toast(result.error || 'Failed to clear sessions', 'error');
        }
    },
    
    // Copy loader script
    copyLoader() {
        const loader = `loadstring(game:HttpGet("${CONFIG.API_BASE}/loader"))()`;
        Utils.copyToClipboard(loader);
    },
    
    // Load recent activity
    async loadRecentActivity() {
        const container = document.getElementById('recentActivity');
        if (!container) return;
        
        const result = await API.getLogs(5);
        
        if (result.success && result.logs && result.logs.length > 0) {
            container.innerHTML = result.logs.map(log => `
                <div class="activity-item">
                    <div class="activity-icon ${log.success ? 'success' : 'danger'}">
                        ${log.success ? '✓' : '✕'}
                    </div>
                    <div class="activity-content">
                        <div class="activity-title">${Utils.escapeHtml(log.action || 'Unknown')}</div>
                        <div class="activity-meta">
                            ${Utils.escapeHtml(Utils.truncate(log.ip || 'N/A', 15))} • ${Utils.formatDate(log.ts)}
                        </div>
                    </div>
                    <span class="badge badge-${log.client === 'executor' ? 'success' : 'warning'}">
                        ${Utils.escapeHtml(log.client || 'unknown')}
                    </span>
                </div>
            `).join('');
        } else {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">📭</div>
                    <p class="text-muted">No recent activity</p>
                </div>
            `;
        }
    },
};
