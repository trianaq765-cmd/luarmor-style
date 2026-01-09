require('dotenv').config();

module.exports = {
    ADMIN_KEY: process.env.ADMIN_KEY || 'your-super-secret-admin-key-here', // GANTI INI! Minimal 32 karakter
    SECRET_KEY: process.env.SECRET_KEY || 'your-super-secret-key-32chars!', // GANTI INI! Minimal 32 karakter
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL || '', // URL raw script Lua Anda

    REDIS_URL: process.env.REDIS_URL || '', // URL Redis untuk persistence data

    LOADER_KEY: process.env.LOADER_KEY || process.env.SECRET_KEY || 'loader-encryption-key-here', // Key untuk enkripsi loader
    DISCORD_WEBHOOK: process.env.DISCORD_WEBHOOK || '', // URL Discord Webhook

    OWNER_USER_IDS: process.env.OWNER_USER_IDS // Daftar User ID owner (script akan mati jika owner join server)
        ? process.env.OWNER_USER_IDS.split(',').map(Number).filter(Boolean)
        : [],
    WHITELIST_USER_IDS: process.env.WHITELIST_USER_IDS // User ID yang bypass semua proteksi
        ? process.env.WHITELIST_USER_IDS.split(',').map(Number).filter(Boolean)
        : [],
    WHITELIST_HWIDS: process.env.WHITELIST_HWIDS // HWID yang bypass semua proteksi
        ? process.env.WHITELIST_HWIDS.split(',').filter(Boolean)
        : [],
    WHITELIST_IPS: process.env.WHITELIST_IPS // IP yang bypass deteksi bot/blocking (untuk cron job, uptime robot)
        ? process.env.WHITELIST_IPS.split(',').map(ip => ip.trim()).filter(Boolean)
        : [],
    
    ALLOWED_PLACE_IDS: process.env.ALLOWED_PLACE_IDS // Hanya izinkan script berjalan di Place ID ini
        ? process.env.ALLOWED_PLACE_IDS.split(',').map(Number).filter(Boolean)
        : [],
    REQUIRE_HWID: process.env.REQUIRE_HWID === 'true', // Wajib ada HWID untuk akses

    SCRIPT_ALREADY_OBFUSCATED: process.env.SCRIPT_ALREADY_OBFUSCATED === 'true', // Set true jika script sudah diobfuscate
    
    ENCODE_LOADER: process.env.ENCODE_LOADER !== 'false', // Encode loader untuk menyulitkan dump
    CHUNK_DELIVERY: process.env.CHUNK_DELIVERY !== 'false', // Pengiriman script per chunk (anti-dump)
    CHUNK_COUNT: parseInt(process.env.CHUNK_COUNT) || 3, // Jumlah chunk script (min 2, default 3)

    ANTI_SPY_ENABLED: process.env.ANTI_SPY_ENABLED !== 'false', // Aktifkan anti-spy tool detection dalam script wrapper
    AUTO_BAN_SPYTOOLS: process.env.AUTO_BAN_SPYTOOLS === 'true', // Auto-ban jika terdeteksi spy tool

    PORT: process.env.PORT || 3000
};
