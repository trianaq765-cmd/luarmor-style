# 🛡️ Luarmor-Style Admin Dashboard

Script protection system dengan fitur HWID control, ban management, dan anti-detection.

## 🚀 Quick Deploy ke Render

1. Fork repo ini
2. Buat akun di [Render.com](https://render.com)
3. New > Web Service > Connect GitHub
4. Pilih repo > Configure environment variables
5. Deploy!

## ⚙️ Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ADMIN_KEY` | ✅ | Key untuk login admin panel |
| `SECRET_KEY` | ✅ | Key untuk enkripsi script |
| `SCRIPT_SOURCE_URL` | ✅ | URL raw script Lua |
| `REDIS_URL` | ❌ | Redis untuk persistent data |
| `OWNER_USER_IDS` | ❌ | Roblox User IDs owner |
| `WHITELIST_USER_IDS` | ❌ | Bypass protection |
| `ALLOWED_PLACE_IDS` | ❌ | Restrict ke game tertentu |

## 📖 Usage

### Loader Script (untuk executor)
```lua
loadstring(game:HttpGet("https://your-app.onrender.com/loader"))()
