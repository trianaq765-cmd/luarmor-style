/* ============================================
   UTILS - Helper Functions
   ============================================ */

const Utils = {
    // ===== Toast Notifications =====
    toast(message, type = 'info', title = null) {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        
        const icons = {
            success: '✓',
            error: '✕',
            warning: '⚠',
            info: 'ℹ',
        };
        
        const titles = {
            success: 'Success',
            error: 'Error',
            warning: 'Warning',
            info: 'Info',
        };
        
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || icons.info}</div>
            <div class="toast-content">
                <div class="toast-title">${title || titles[type]}</div>
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
        `;
        
        container.appendChild(toast);
        
        // Trigger animation
        requestAnimationFrame(() => {
            toast.classList.add('show');
        });
        
        // Auto remove
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, CONFIG.TOAST_DURATION);
    },
    
    // ===== Date Formatting =====
    formatDate(dateString, options = {}) {
        if (!dateString) return 'N/A';
        
        const date = new Date(dateString);
        const now = new Date();
        const diff = now - date;
        
        // Relative time for recent dates
        if (options.relative !== false) {
            if (diff < 60000) return 'Just now';
            if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
            if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
            if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
        }
        
        // Full date
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined,
            hour: '2-digit',
            minute: '2-digit',
        });
    },
    
    formatTime(dateString) {
        if (!dateString) return 'N/A';
        return new Date(dateString).toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    },
    
    // ===== String Helpers =====
    truncate(str, length = 20) {
        if (!str) return '';
        if (str.length <= length) return str;
        return str.substring(0, length) + '...';
    },
    
    capitalize(str) {
        if (!str) return '';
        return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
    },
    
    // ===== Number Formatting =====
    formatNumber(num) {
        if (num === null || num === undefined) return '0';
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toLocaleString();
    },
    
    // ===== Copy to Clipboard =====
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.toast('Copied to clipboard', 'success');
            return true;
        } catch (err) {
            this.toast('Failed to copy', 'error');
            return false;
        }
    },
    
    // ===== Debounce =====
    debounce(func, wait = 300) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    // ===== Confirmation Dialog =====
    async confirm(message, title = 'Confirm') {
        return new Promise((resolve) => {
            const overlay = document.getElementById('confirmModal');
            const titleEl = document.getElementById('confirmTitle');
            const messageEl = document.getElementById('confirmMessage');
            const confirmBtn = document.getElementById('confirmBtn');
            const cancelBtn = document.getElementById('confirmCancelBtn');
            
            titleEl.textContent = title;
            messageEl.textContent = message;
            overlay.classList.add('active');
            
            const cleanup = () => {
                overlay.classList.remove('active');
                confirmBtn.onclick = null;
                cancelBtn.onclick = null;
            };
            
            confirmBtn.onclick = () => {
                cleanup();
                resolve(true);
            };
            
            cancelBtn.onclick = () => {
                cleanup();
                resolve(false);
            };
        });
    },
    
    // ===== Element Helpers =====
    $(selector) {
        return document.querySelector(selector);
    },
    
    $$(selector) {
        return document.querySelectorAll(selector);
    },
    
    // ===== Escape HTML =====
    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },
    
    // ===== Generate ID =====
    generateId() {
        return 'id_' + Math.random().toString(36).substr(2, 9);
    },
    
    // ===== Loading State =====
    setLoading(element, loading = true) {
        if (loading) {
            element.classList.add('loading');
            element.disabled = true;
        } else {
            element.classList.remove('loading');
            element.disabled = false;
        }
    },
};
