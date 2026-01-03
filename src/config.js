// ============================================================
// ⚙️ CONFIGURATION
// ============================================================

module.exports = {
    // Server
    PORT: process.env.PORT || 3000,
    
    // Script Source (GitHub raw URL)
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL || '',
    
    // Ban Endpoint (will be auto-set)
    BAN_ENDPOINT: process.env.RENDER_EXTERNAL_URL 
        ? `${process.env.RENDER_EXTERNAL_URL}/api/ban`
        : process.env.BAN_ENDPOINT || '',
    
    // Webhook for notifications (optional)
    WEBHOOK_URL: process.env.WEBHOOK_URL || '',
    
    // Admin
    ADMIN_KEY: process.env.ADMIN_KEY || 'change-this-to-secure-key',
    
    // Rate Limiting
    RATE_LIMIT: {
        WINDOW_MS: 60 * 1000,
        MAX_REQUESTS: 60
    },
    
    // Cache Settings
    CACHE: {
        TTL: 300, // 5 minutes
        CHECK_PERIOD: 60
    }
};
