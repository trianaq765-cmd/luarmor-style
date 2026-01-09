/* ============================================
   BANS - Ban Management
   ============================================ */

const Bans = {
    bans: [],
    filteredBans: [],
    searchQuery: '',
    
    // Initialize
    async init() {
        await this.loadBans();
        this.bindEvents();
    },
    
    // Load bans from API
    async loadBans() {
        const result = await API.getBans();
        
        if (result.success) {
            this.bans = result.bans || [];
            this.filterBans();
            this.renderTable();
        } else {
            Utils.toast('Failed to load bans', 'error');
        }
    },
    
    // Filter bans based on search
    filterBans() {
        if (!this.searchQuery) {
            this.filteredBans = [...this.bans];
        } else {
            const query = this.searchQuery.toLowerCase();
            this.filteredBans = this.bans.filter(ban => 
                (ban.hwid && ban.hwid.toLowerCase().includes(query)) ||
                (ban.ip && ban.ip.toLowerCase().includes(query)) ||
                (ban.playerId && String(ban.playerId).includes(query)) ||
                (ban.reason && ban.reason.toLowerCase().includes(query)) ||
                (ban.banId && ban.banId.toLowerCase().includes(query))
            );
        }
    },
    
    // Render bans table
    renderTable() {
        const tbody = document.getElementById('bansTableBody');
        if (!tbody) return;
        
        if (this.filteredBans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center" style="padding: 40px;">
                        <div class="empty-state">
                            <div class="empty-state-icon">🎉</div>
                            <h4 class="empty-state-title">No bans found</h4>
                            <p class="empty-state-text">
                                ${this.searchQuery ? 'Try a different search term' : 'Your ban list is empty'}
                            </p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = this.filteredBans.map(ban => `
            <tr class="animate-fadeIn">
                <td>
                    <code class="text-primary">${Utils.escapeHtml(ban.banId || 'N/A')}</code>
                </td>
                <td>
                    <div class="cell-stack">
                        ${ban.hwid ? `<span class="badge badge-purple" title="${Utils.escapeHtml(ban.hwid)}">HWID: ${Utils.truncate(ban.hwid, 12)}</span>` : ''}
                        ${ban.ip ? `<span class="badge badge-info" title="${Utils.escapeHtml(ban.ip)}">IP: ${Utils.truncate(ban.ip, 15)}</span>` : ''}
                        ${ban.playerId ? `<span class="badge badge-warning">ID: ${ban.playerId}</span>` : ''}
                    </div>
                </td>
                <td class="text-secondary">${Utils.escapeHtml(ban.reason || 'No reason')}</td>
                <td class="text-muted">${Utils.formatDate(ban.ts)}</td>
                <td>
                    <div class="table-actions">
                        <button class="btn btn-ghost btn-icon btn-sm" onclick="Bans.copyBan('${ban.banId}')" title="Copy">
                            📋
                        </button>
                        <button class="btn btn-danger btn-icon btn-sm" onclick="Bans.removeBan('${ban.banId}')" title="Remove">
                            🗑️
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    },
    
    // Bind event listeners
    bindEvents() {
        const searchInput = document.getElementById('banSearch');
        if (searchInput) {
            searchInput.addEventListener('input', Utils.debounce((e) => {
                this.searchQuery = e.target.value;
                this.filterBans();
                this.renderTable();
            }, 300));
        }
    },
    
    // Open add ban modal
    openAddModal() {
        const modal = document.getElementById('addBanModal');
        if (modal) {
            modal.classList.add('active');
            // Reset form
            document.getElementById('banHwid').value = '';
            document.getElementById('banPlayerId').value = '';
            document.getElementById('banIp').value = '';
            document.getElementById('banReason').value = '';
        }
    },
    
    // Close add ban modal
    closeAddModal() {
        const modal = document.getElementById('addBanModal');
        if (modal) {
            modal.classList.remove('active');
        }
    },
    
    // Add new ban
    async addBan() {
        const hwid = document.getElementById('banHwid').value.trim();
        const playerId = document.getElementById('banPlayerId').value.trim();
        const ip = document.getElementById('banIp').value.trim();
        const reason = document.getElementById('banReason').value.trim();
        
        if (!hwid && !playerId && !ip) {
            Utils.toast('Enter at least one identifier (HWID, Player ID, or IP)', 'error');
            return;
        }
        
        const btn = document.getElementById('addBanBtn');
        Utils.setLoading(btn, true);
        
        const result = await API.addBan({
            hwid: hwid || undefined,
            playerId: playerId ? parseInt(playerId) : undefined,
            ip: ip || undefined,
            reason: reason || 'Manual ban',
        });
        
        Utils.setLoading(btn, false);
        
        if (result.success) {
            Utils.toast(`Ban added: ${result.banId}`, 'success');
            this.closeAddModal();
            this.loadBans();
            Dashboard.loadStats();
        } else {
            Utils.toast(result.error || 'Failed to add ban', 'error');
        }
    },
    
    // Remove ban
    async removeBan(banId) {
        const confirmed = await Utils.confirm(
            'Are you sure you want to remove this ban?',
            'Remove Ban'
        );
        
        if (!confirmed) return;
        
        const result = await API.removeBan(banId);
        
        if (result.success) {
            Utils.toast('Ban removed', 'success');
            this.loadBans();
            Dashboard.loadStats();
        } else {
            Utils.toast(result.error || 'Failed to remove ban', 'error');
        }
    },
    
    // Clear all bans
    async clearAll() {
        const confirmed = await Utils.confirm(
            'This will remove ALL bans. This action cannot be undone!',
            '⚠️ Clear All Bans?'
        );
        
        if (!confirmed) return;
        
        const result = await API.clearAllBans();
        
        if (result.success) {
            Utils.toast(`Cleared ${result.cleared || 0} bans`, 'success');
            this.loadBans();
            Dashboard.loadStats();
        } else {
            Utils.toast(result.error || 'Failed to clear bans', 'error');
        }
    },
    
    // Copy ban ID
    copyBan(banId) {
        Utils.copyToClipboard(banId);
    },
    
    // Refresh bans
    async refresh() {
        const btn = document.querySelector('.refresh-bans-btn');
        if (btn) btn.classList.add('animate-spin');
        
        await this.loadBans();
        
        if (btn) {
            setTimeout(() => btn.classList.remove('animate-spin'), 500);
        }
        
        Utils.toast('Bans refreshed', 'success');
    },
    
    // Render page
    render() {
        return `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Ban Management</h1>
                    <p class="page-subtitle">Manage banned HWIDs, IPs, and Player IDs</p>
                </div>
            </div>
            
            <div class="card animate-fadeInUp">
                <div class="card-header">
                    <div class="actions-left">
                        <div class="search-input-wrapper">
                            <span class="search-icon">🔍</span>
                            <input type="text" id="banSearch" class="form-input" placeholder="Search bans..." style="padding-left: 40px; width: 300px;">
                        </div>
                    </div>
                    <div class="actions-right">
                        <button class="btn btn-ghost refresh-bans-btn" onclick="Bans.refresh()">
                            ↻ Refresh
                        </button>
                        <button class="btn btn-danger" onclick="Bans.clearAll()">
                            🗑️ Clear All
                        </button>
                        <button class="btn btn-primary" onclick="Bans.openAddModal()">
                            ➕ Add Ban
                        </button>
                    </div>
                </div>
                <div class="table-container">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Ban ID</th>
                                <th>Identifier</th>
                                <th>Reason</th>
                                <th>Date</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="bansTableBody">
                            <tr>
                                <td colspan="5" class="text-center" style="padding: 40px;">
                                    <div class="spinner"></div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Add Ban Modal -->
            <div class="modal-overlay" id="addBanModal">
                <div class="modal">
                    <div class="modal-header">
                        <h3 class="modal-title">➕ Add New Ban</h3>
                        <button class="modal-close" onclick="Bans.closeAddModal()">✕</button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">HWID</label>
                            <input type="text" id="banHwid" class="form-input" placeholder="Enter HWID (optional)">
                            <p class="form-help">Hardware ID of the user</p>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Player ID</label>
                            <input type="number" id="banPlayerId" class="form-input" placeholder="Enter Roblox User ID (optional)">
                            <p class="form-help">Roblox user ID</p>
                        </div>
                        <div class="form-group">
                            <label class="form-label">IP Address</label>
                            <input type="text" id="banIp" class="form-input" placeholder="Enter IP (optional)">
                            <p class="form-help">IP address to ban</p>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Reason</label>
                            <input type="text" id="banReason" class="form-input" placeholder="Enter reason" value="Manual ban">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" onclick="Bans.closeAddModal()">Cancel</button>
                        <button class="btn btn-danger" id="addBanBtn" onclick="Bans.addBan()">🚫 Add Ban</button>
                    </div>
                </div>
            </div>
        `;
    },
};
