require('dotenv').config();

module.exports = {
    // ==================== REQUIRED ====================
    ADMIN_KEY: process.env.ADMIN_KEY || 'change-this-to-secure-key-min-32-chars',
    SECRET_KEY: process.env.SECRET_KEY || 'another-secret-key-for-encryption-32',
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL || '',

    // ==================== OPTIONAL ====================
    REDIS_URL: process.env.REDIS_URL || '',
    
    OWNER_USER_IDS: process.env.OWNER_USER_IDS 
        ? process.env.OWNER_USER_IDS.split(',').map(Number).filter(Boolean) 
        : [],
    
    WHITELIST_USER_IDS: process.env.WHITELIST_USER_IDS
        ? process.env.WHITELIST_USER_IDS.split(',').map(Number).filter(Boolean)
        : [],
    
    ALLOWED_PLACE_IDS: process.env.ALLOWED_PLACE_IDS
        ? process.env.ALLOWED_PLACE_IDS.split(',').map(Number).filter(Boolean)
        : [],
    
    SCRIPT_ALREADY_OBFUSCATED: process.env.SCRIPT_ALREADY_OBFUSCATED === 'true',
    PORT: process.env.PORT || 3000
};
