/* ============================================
   APP - Main Application Controller (FIXED)
   ============================================ */

const App = {
    currentPage: 'dashboard',
    initialized: false,
    
    // Initialize application
    async init() {
        if (this.initialized) return;
        
        console.log('[App] Initializing...');
        
        // Show loading state
        this.showLoadingState();
        
        // Check authentication
        const isAuth = await Auth.check();
        
        if (isAuth) {
            console.log('[App] User authenticated, showing dashboard');
            this.showDashboard();
        } else {
            console.log('[App] User not authenticated, showing login');
            this.showLogin();
        }
        
        this.bindGlobalEvents();
        this.initialized = true;
    },
    
    // Show loading state
    showLoadingState() {
        const loginScreen = document.getElementById('loginScreen');
        const loginBtn = document.getElementById('loginBtn');
        
        if (loginBtn) {
            loginBtn.disabled = true;
            loginBtn.innerHTML = '<span class="spinner spinner-sm"></span> Checking...';
        }
    },
    
    // Show login screen
    showLogin() {
        const loginScreen = document.getElementById('loginScreen');
        const dashboardScreen = document.getElementById('dashboardScreen');
        const loginBtn = document.getElementById('loginBtn');
        const loginError = document.getElementById('loginError');
        
        if (loginScreen) loginScreen.classList.remove('hidden');
        if (dashboardScreen) dashboardScreen.classList.add('hidden');
        
        // Reset login button
        if (loginBtn) {
            loginBtn.disabled = false;
            loginBtn.innerHTML = '🚀 Login';
        }
        
        // Hide error
        if (loginError) loginError.classList.add('hidden');
        
        // Focus on input
        setTimeout(() => {
            const input = document.getElementById('adminKeyInput');
            if (input) {
                input.value = '';
                input.focus();
            }
        }, 100);
    },
    
    // Show dashboard
    showDashboard() {
        const loginScreen = document.getElementById('loginScreen');
        const dashboardScreen = document.getElementById('dashboardScreen');
        
        if (loginScreen) loginScreen.classList.add('hidden');
        if (dashboardScreen) dashboardScreen.classList.remove('hidden');
        
        // Navigate to default page
        this.navigate('dashboard');
    },
    
    // Handle login
    async login() {
        const input = document.getElementById('adminKeyInput');
        const btn = document.getElementById('loginBtn');
        const errorEl = document.getElementById('loginError');
        const errorText = document.getElementById('loginErrorText');
        
        if (!input || !btn) {
            console.error('[App] Login elements not found');
            return;
        }
        
        const key = input.value;
        
        // Clear previous error
        if (errorEl) errorEl.classList.add('hidden');
        input.classList.remove('error');
        
        // Validate
        if (!key || key.trim().length === 0) {
            this.showLoginError('Masukkan admin key', input, errorEl, errorText);
            return;
        }
        
        // Loading state
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner spinner-sm"></span> Verifying...';
        
        console.log('[App] Starting login...');
        
        try {
            const result = await Auth.login(key);
            
            if (result.success) {
                // Success
                btn.innerHTML = '✓ Success!';
                btn.classList.add('btn-success');
                
                setTimeout(() => {
                    this.showDashboard();
                    Utils.toast('Welcome to Script Shield!', 'success');
                    
                    // Reset button for next time
                    btn.classList.remove('btn-success');
                    btn.innerHTML = '🚀 Login';
                    btn.disabled = false;
                }, 500);
                
            } else {
                // Failed
                this.showLoginError(result.error || 'Invalid admin key', input, errorEl, errorText);
                btn.disabled = false;
                btn.innerHTML = '🚀 Login';
            }
        } catch (err) {
            console.error('[App] Login error:', err);
            this.showLoginError('Terjadi kesalahan: ' + err.message, input, errorEl, errorText);
            btn.disabled = false;
            btn.innerHTML = '🚀 Login';
        }
    },
    
    // Show login error
    showLoginError(message, input, errorEl, errorText) {
        if (errorText) errorText.textContent = message;
        if (errorEl) errorEl.classList.remove('hidden');
        if (input) {
            input.classList.add('error');
            input.classList.add('animate-shake');
            setTimeout(() => input.classList.remove('animate-shake'), 500);
            input.focus();
            input.select();
        }
    },
    
    // Navigate to page
    navigate(page) {
        // Cleanup previous page
        if(this.currentPage==='logs')Logs.destroy();
if(this.currentPage==='sessions')Sessions.destroy();
this.currentPage=page;
const pageNameEl=document.getElementById('currentPageName');
if(pageNameEl){const names={dashboard:'Dashboard',bans:'Ban Management',logs:'Activity Logs',settings:'Settings',whitelist:'Whitelist',sessions:'Active Sessions',suspended:'Suspended Users'};pageNameEl.textContent=names[page]||'Dashboard'}
document.querySelectorAll('.nav-item').forEach(item=>{item.classList.remove('active');if(item.dataset.page===page)item.classList.add('active')});
const content=document.getElementById('pageContent');
if(!content)return;
content.innerHTML=`<div class="empty-state"><div class="spinner spinner-lg"></div></div>`;
setTimeout(()=>{switch(page){case'dashboard':content.innerHTML=Dashboard.render();Dashboard.init();Dashboard.loadRecentActivity();break;case'bans':content.innerHTML=Bans.render();Bans.init();break;case'logs':content.innerHTML=Logs.render();Logs.init();break;case'whitelist':content.innerHTML=Whitelist.render();Whitelist.init();break;case'sessions':content.innerHTML=Sessions.render();Sessions.init();break;case'suspended':content.innerHTML=Suspended.render();Suspended.init();break;case'settings':content.innerHTML=this.renderSettings();break;default:content.innerHTML=Dashboard.render();Dashboard.init()}},100);
content.scrollTop=0;
const sidebar=document.getElementById('sidebar');
if(sidebar&&window.innerWidth<=1024)sidebar.classList.remove('open');
        }
        
        this.currentPage = page;
        
        // Update page name in header
        const pageNameEl = document.getElementById('currentPageName');
        if (pageNameEl) {
            const names = {
                dashboard: 'Dashboard',
                bans: 'Ban Management',
                logs: 'Activity Logs',
                settings: 'Settings'
            };
            pageNameEl.textContent = names[page] || 'Dashboard';
        }
        
        // Update sidebar active state
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.page === page) {
                item.classList.add('active');
            }
        });
        
        // Render page content
        const content = document.getElementById('pageContent');
        if (!content) return;
        
        // Show loading
        content.innerHTML = `
            <div class="empty-state">
                <div class="spinner spinner-lg"></div>
                <p class="text-muted" style="margin-top: var(--space-4);">Loading...</p>
            </div>
        `;
        
        // Render page after brief delay (for animation)
        setTimeout(() => {
            switch (page) {
                case 'dashboard':
                    content.innerHTML = Dashboard.render();
                    Dashboard.init();
                    Dashboard.loadRecentActivity();
                    break;
                case 'bans':
                    content.innerHTML = Bans.render();
                    Bans.init();
                    break;
                case 'logs':
                    content.innerHTML = Logs.render();
                    Logs.init();
                    break;
                case 'settings':
                    content.innerHTML = this.renderSettings();
                    break;
                case'whitelist':
                    content.innerHTML=Whitelist.render();
                    Whitelist.init();
                    break;
                default:
                    content.innerHTML = Dashboard.render();
                    Dashboard.init();
            }
        }, 100);
        
        // Scroll to top
        content.scrollTop = 0;
    },
    
    // Render settings page
    renderSettings() {
        return `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Settings</h1>
                    <p class="page-subtitle">Configure your admin dashboard</p>
                </div>
            </div>
            
            <div class="content-grid">
                <div class="card animate-fadeInUp">
                    <div class="card-header">
                        <h3 class="card-title">
                            <span class="card-title-icon">🔑</span>
                            Authentication
                        </h3>
                    </div>
                    <div class="card-body">
                        <div class="form-group">
                            <label class="form-label">Current Admin Key</label>
                            <div class="input-with-button">
                                <input type="text" class="form-input" value="${Auth.getMaskedKey()}" readonly>
                                <button class="btn btn-danger" onclick="Auth.logout()">Logout</button>
                            </div>
                            <p class="form-help">Key tersimpan di browser local storage</p>
                        </div>
                    </div>
                </div>
                
                <div class="card animate-fadeInUp">
                    <div class="card-header">
                        <h3 class="card-title">
                            <span class="card-title-icon">📋</span>
                            Loader Script
                        </h3>
                    </div>
                    <div class="card-body">
                        <div class="form-group">
                            <label class="form-label">Copy this to your executor:</label>
                            <div class="code-block">
                                <pre><code>loadstring(game:HttpGet("${CONFIG.API_BASE}/loader"))()</code></pre>
                                <button class="btn btn-primary btn-sm copy-code-btn" onclick="Dashboard.copyLoader()">
                                    📋 Copy
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card animate-fadeInUp">
                    <div class="card-header">
                        <h3 class="card-title">
                            <span class="card-title-icon">ℹ️</span>
                            System Info
                        </h3>
                    </div>
                    <div class="card-body">
                        <div class="info-list">
                            <div class="info-item">
                                <span class="info-label">Server URL</span>
                                <span class="info-value">${CONFIG.API_BASE}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Version</span>
                                <span class="info-value">1.0.0</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Status</span>
                                <span class="badge badge-success">● Online</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },
    
    // Toggle sidebar (mobile)
    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.toggle('open');
        }
    },
    
    // Bind global events
    bindGlobalEvents() {
        // Login form enter key
        const loginInput = document.getElementById('adminKeyInput');
        if (loginInput) {
            loginInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.login();
                }
            });
        }
        
        // Login button click
        const loginBtn = document.getElementById('loginBtn');
        if (loginBtn) {
            loginBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.login();
            });
        }
        
        // Close modals on escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal-overlay.active').forEach(modal => {
                    modal.classList.remove('active');
                });
            }
        });
        
        // Close modals on overlay click
        document.querySelectorAll('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) {
                    overlay.classList.remove('active');
                }
            });
        });
        
        // Navigation items
        document.querySelectorAll('.nav-item[data-page]').forEach(item => {
            item.addEventListener('click', () => {
                const page = item.dataset.page;
                if (page) this.navigate(page);
                
                // Close sidebar on mobile
                const sidebar = document.getElementById('sidebar');
                if (sidebar && window.innerWidth <= 1024) {
                    sidebar.classList.remove('open');
                }
            });
        });
    },
};

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('[App] DOM loaded, initializing...');
    App.init();
});

// Also handle if DOM already loaded
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    console.log('[App] DOM already ready, initializing...');
    setTimeout(() => App.init(), 1);
}
