# 🛡️ Premium Loader v4.0.0 - Full Security Edition

## Features

- ✅ **Anti-Debug** - Detects debug tools and hooks
- ✅ **Anti-Dump** - Prevents script dumping
- ✅ **Anti-Decompile** - Makes decompilation difficult
- ✅ **Anti-Tamper** - Verifies script integrity
- ✅ **Tool Detection** - Detects Dex, Hydroxide, SimpleSpy, etc.
- ✅ **Auto-Ban System** - Bans malicious users automatically
- ✅ **Continuous Monitoring** - Checks for tools every 5 seconds

## Detected Tools

- Dex Explorer (all versions)
- Dark Dex
- Infinite Yield
- Hydroxide
- SimpleSpy / RemoteSpy
- Script Dumpers
- And many more...

## Deployment

### 1. Push to GitHub
\`\`\`bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/premium-loader.git
git push -u origin main
\`\`\`

### 2. Deploy to Render
1. Go to [render.com](https://render.com)
2. Connect GitHub repository
3. Set environment variables:
   - `SCRIPT_SOURCE_URL` = Your raw script URL
   - `ADMIN_KEY` = Your admin key

### 3. Use in Roblox
\`\`\`lua
loadstring(game:HttpGet("https://your-app.onrender.com/script"))()
\`\`\`

## Admin Endpoints

- `GET /api/admin/stats` - View statistics
- `GET /api/admin/logs` - View access logs
- `GET /api/admin/bans` - View banned devices
- `DELETE /api/admin/bans/:banId` - Remove a ban
- `POST /api/admin/cache/clear` - Clear script cache
- `POST /api/admin/refresh` - Refresh script from source

All admin endpoints require `x-admin-key` header.
