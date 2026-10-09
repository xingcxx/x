/**
 * 名称： Chunlion_Rule-Set_DNS-Leak 覆写脚本（DNS 防泄漏优化版）
 * 说明： 基于 YAML 配置文件生成的 JS 脚本，用于 Mihomo 内核客户端的 Merge 覆写。
 *
 * 优化（2026-09-27，基于开源社区防泄漏最佳实践）：
 *  1. 全局 nameserver 改用 Cloudflare / Google DoH（IP 直连形式，免去 bootstrap 查询），
 *     并通过 Mihomo 扩展语法 "#一键代理" 让 DoH 查询本身经代理出站 ——
 *     境外域名的 DNS 查询不再经过阿里 / 腾讯，本地 ISP 与国内解析商全程不可见。
 *  2. proxy-server-nameserver 保持国内 DoH 直连（解析节点 server 域名），
 *     避免"解析依赖代理、代理依赖解析"的死锁；国内 DoH 抗污染、直连可达。
 *  3. 新增 TCP 853（DoT）显式走代理规则：硬编码 DoT 的应用也不会直连境外 853。
 *  4. 延续原有正确设计：无 fallback（fallback 请求不走代理本身就是泄漏源）、
 *     respect-rules: true、direct-nameserver-follow-policy: true、ipv6: false、
 *     TUN dns-hijack 劫持 53 端口。
 *
 * 注意：nameserver 的 "#代理组" 后缀为 Mihomo 内核扩展语法，
 *      需要 Mihomo 核心的客户端（如 Clash Verge / FlClash / Mihomo Party）。
 *      若客户端不支持导致 DNS 异常，把 nameserver 改回不带后缀的
 *      'https://1.1.1.1/dns-query' 即可（respect-rules 仍会按规则路由）。
 */

function collectPrivateNameservers(dnsConfig = {}) {
  const publicNameserverHosts = [
    '223.5.5.5', '223.6.6.6', '119.29.29.29', '1.12.12.12', '120.53.53.53',
    '114.114.114.114', '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4',
    '9.9.9.9', '127.0.0.1'
  ];
  const publicNameserverKeywords = [
    'alidns', 'doh.pub', 'dot.pub', 'dnspod', 'dns.google', 'cloudflare',
    'quad9', 'opendns', 'nextdns', 'adguard', 'system'
  ];
  const candidates = [
    ...(Array.isArray(dnsConfig['nameserver']) ? dnsConfig['nameserver'] : []),
    ...(Array.isArray(dnsConfig['proxy-server-nameserver']) ? dnsConfig['proxy-server-nameserver'] : [])
  ];
  return [...new Set(candidates
    .filter(nameserver => typeof nameserver === 'string')
    .map(nameserver => nameserver.trim())
    .filter(Boolean))]
    .filter(nameserver => {
      const normalized = nameserver.toLowerCase();
      const host = normalized.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/:#?]/, 1)[0];
      return !publicNameserverHosts.includes(host)
        && !publicNameserverKeywords.some(keyword => normalized.includes(keyword));
    });
}

function collectProxyServerDomains(proxies = []) {
  return new Set((Array.isArray(proxies) ? proxies : [])
    .map(proxy => proxy && proxy.server)
    .filter(server => typeof server === 'string')
    .map(server => server.trim().toLowerCase())
    .filter(Boolean));
}

function hostPatternMatchesDomains(pattern, domains, preserveUnknown = false) {
  if (typeof pattern !== 'string') {
    return false;
  }
  return pattern.split(',').some(rawPattern => {
    const candidate = rawPattern.trim().toLowerCase();
    if (!candidate || candidate.startsWith('rule-set:') || candidate.startsWith('geosite:')) {
      return false;
    }
    if (preserveUnknown) return true;
    const suffix = candidate.startsWith('+.')
      || candidate.startsWith('*.')
      ? candidate.slice(2)
      : candidate.startsWith('.') ? candidate.slice(1) : null;
    return suffix
      ? [...domains].some(domain => domain === suffix || domain.endsWith(`.${suffix}`))
      : domains.has(candidate);
  });
}

function collectProxyDomainMappings(sources, domains, preserveUnknown = false) {
  const mappings = {};
  for (const source of sources) {
    if (!source || typeof source !== 'object' || Array.isArray(source)) {
      continue;
    }
    for (const [pattern, value] of Object.entries(source)) {
      if (hostPatternMatchesDomains(pattern, domains, preserveUnknown)) {
        mappings[pattern] = value;
      }
    }
  }
  return mappings;
}

function main(config) {
  const originalDnsConfig = config['dns'] || {};
  const providers = Object.values(config['proxy-providers'] || {});
  const proxyServerDomains = collectProxyServerDomains([
    ...(Array.isArray(config['proxies']) ? config['proxies'] : []),
    ...providers.flatMap(provider => Array.isArray(provider.payload) ? provider.payload : [])
  ]);

  // HTTP/file 集合在覆写阶段尚未展开，保留显式域名映射供后续节点解析。
  const preserveUnknown = providers.some(provider => provider.type === 'http' || provider.type === 'file');
  const privateNameservers = collectPrivateNameservers(originalDnsConfig);
  const proxyServerPolicy = collectProxyDomainMappings([
    originalDnsConfig['nameserver-policy'],
    originalDnsConfig['proxy-server-nameserver-policy']
  ], proxyServerDomains, preserveUnknown);
  const proxyServerHosts = collectProxyDomainMappings([config['hosts']], proxyServerDomains, preserveUnknown);

  // ==================== 基础配置 ====================
  config['mixed-port'] = 7893;
  config['mode'] = 'rule';
  config['find-process-mode'] = 'strict';
  config['allow-lan'] = false;
  config['bind-address'] = '127.0.0.1';
  config['tcp-concurrent'] = true;
  config['unified-delay'] = true;
  config['keep-alive-idle'] = 600;
  config['keep-alive-interval'] = 60;
  config['log-level'] = 'info';
  config['ipv6'] = false;
  config['profile'] = {
    'store-selected': true,
    'store-fake-ip': true,
  };
  config['ntp'] = {
    'enable': true,
    'write-to-system': false,
    'server': 'time.apple.com',
    'port': 123,
    'interval': 30,
    'dialer-proxy': 'DIRECT',
  };
  config['external-controller'] = '127.0.0.1:9090';
  config['external-ui'] = 'ui';

  if (typeof config['secret'] !== 'string' || !config['secret'].trim()) {
    config['secret'] = '123456';
  }

  delete config['global-client-fingerprint'];
  config['external-ui-url'] = 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist-no-fonts.zip';

  // ==================== TUN 配置 ====================
  // 注意: stack 使用 gvisor 而非 mixed。mixed 下 TCP 走系统协议栈、
  // UDP 走 gVisor,在 iOS/Hako 上曾观察到 TCP 流量绕过隧道直连、
  // 而 UDP 正常走代理的分裂现象。gvisor 为纯用户态协议栈,
  // TCP/UDP 统一处理,对隧道捕获最可靠。
  config['tun'] = {
    'enable': true,
    'stack': 'gvisor',
    'dns-hijack': ['any:53', 'tcp://any:53'],
    'auto-detect-interface': true,
    'auto-route': true,
    'auto-redirect': true,
    'strict-route': false,
    'endpoint-independent-nat': true,
    'mtu': 1500, // 显式设定 MTU 为 1500，避免 macOS 虚拟网卡默认 4064 导致 TCP 分片、丢包及 TLS 握手延迟
    'route-exclude-address-set': ['cn_ip'],
  };

  // ==================== 嗅探功能 ====================
  config['sniffer'] = {
    'enable': true,
    'override-destination': false,
    'parse-pure-ip': false,
    'force-dns-mapping': true,
    'sniff': {
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'TLS': { 'ports': [443, 8443] },
      'QUIC': { 'ports': [443, 8443] }
    },
    'force-domain': [
      '+.netflix.com',
      '+.nflxvideo.net',
      '+.media.dssott.com',
    ],
    'skip-domain': [
      '+.apple.com',
      'Mijia Cloud',
      'dlg.io.mi.com',
      '+.oray.com',
      '+.sunlogin.net',
    ],
    'skip-dst-address': [
      '127.0.0.0/8',
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16',
      '169.254.0.0/16',
      '100.64.0.0/10',
      '::1/128',
      'fc00::/7',
      'fe80::/10',
    ],
  };

  config['hosts'] = {
    'services.googleapis.cn': ['services.googleapis.com'],
    ...proxyServerHosts,
  };

  // Apple Intelligence / Siri：来自用户提供的 Apple 规则集，统一经非中国出口解析及访问。
  // DOMAIN 与 DOMAIN-SUFFIX 分开保留，避免把精确匹配意外扩展为泛域名匹配。
  const appleIntelligenceDomainRules = [
    'guzzoni.apple.com',
    'mask-api.fe.apple-dns.net',
    'mask-api.icloud.com',
    'mask-t.apple-dns.net',
    'mask.apple-dns.net',
  ];
  const appleIntelligenceSuffixRules = [
    'mask.icloud.com',
    'apps.mastic.com',
    'smoot.apple.com',
    'apple-relay.akamaized.net',
    'apple-relay.apple.com',
    'apple-relay.cloudflare.com',
    'apple-relay.fastly-edge.com',
    'apple-relay.tasty-edge.com',
    'apple-relay.mask.apple-dns.net',
    'cp4.cloudflare.com',
    'gspe1-ssl.ls.apple.com',
    'gateway.icloud.com',
    'ls.apple.com',
    'mask-h2.icloud.com',
  ];
  const appleIntelligenceDnsDomains = [...new Set([
    ...appleIntelligenceDomainRules,
    ...appleIntelligenceSuffixRules,
  ])];
  const proxiedPublicDns = [
    'https://dns.google/dns-query#Apple Intelligence',
    'https://1.1.1.1/dns-query#Apple Intelligence',
    'https://1.0.0.1/dns-query#Apple Intelligence',
    'https://8.8.8.8/dns-query#Apple Intelligence',
    'tls://8.8.8.8#Apple Intelligence',
  ];

  // ==================== DNS 设置（防泄漏优化版） ====================
  config['dns'] = {
    'enable': true,
    'use-hosts': true,
    'use-system-hosts': true,
    'cache-algorithm': 'arc',
    'listen': '127.0.0.1:7874',
    'ipv6': false,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-filter-mode': 'blacklist',
    'respect-rules': true,
    // respect-rules 与 prefer-h3 互斥，必须保持 false
    'prefer-h3': false,
    'fake-ip-filter': [
      'rule-set:fakeip_filter',
      'rule-set:vowifi',
      '+.ts.net',
      '+.3gppnetwork.org',
      '+.lan',
      '+.local',
      'geosite:cn',
      'rule-set:cn_domain',
      'rule-set:private_domain',
      'rule-set:add_direct_domain',
      'rule-set:apple_cn',
      'rule-set:microsoft_cn',
      'rule-set:games_cn_domain',
      'rule-set:douyin_domain',
      '+.msftconnecttest.com',
      '+.msftncsi.com',
      'localhost.ptlogin2.qq.com',
      'localhost.sec.qq.com',
      '+.in-addr.arpa',
      '+.ip6.arpa',
      'stun.*',
      '+.stun.*.*',
      '+.turn.*.*',
      '+.ntp.org',
      'time.windows.com',
      'time.apple.com',
      'time-ios.apple.com',
      'time.google.com',
    ],

    // Bootstrap：只用于解析 DoH 服务器域名与节点 server 域名，必须是纯 IP 且直连
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],

    // 节点 server 域名解析：必须直连可用，避免"解析依赖代理、代理依赖解析"死锁；
    // 用国内 DoH 防污染、保证直连可达。不走代理是刻意为之。
    'proxy-server-nameserver': [
      'https://dns.alidns.com/dns-query',
      'https://doh.pub/dns-query',
      ...privateNameservers,
    ],
    ...(Object.keys(proxyServerPolicy).length > 0 && {
      'proxy-server-nameserver-policy': proxyServerPolicy,
    }),

    // 直连域名解析：国内 DNS，保证国内 CDN 调度正确
    'direct-nameserver': ['223.5.5.5', '119.29.29.29'],
    'direct-nameserver-follow-policy': true,
    'nameserver-policy': {
      // 显式覆盖 apple@cn：Siri/Apple Intelligence 的解析必须从代理出站。
      ...Object.fromEntries(appleIntelligenceDnsDomains.map(domain => [`+.${domain}`, proxiedPublicDns])),
      'geosite:cn,private,apple@cn,microsoft@cn,category-games@cn': ['223.5.5.5', '119.29.29.29'],
      'rule-set:add_direct_domain': ['223.5.5.5', '119.29.29.29'],
      'rule-set:cn_domain': ['223.5.5.5', '119.29.29.29'],
      'rule-set:private_domain': ['223.5.5.5', '119.29.29.29'],
      'rule-set:apple_cn': ['223.5.5.5', '119.29.29.29'],
      'rule-set:microsoft_cn': ['223.5.5.5', '119.29.29.29'],
      'rule-set:games_cn_domain': ['223.5.5.5', '119.29.29.29'],
      'rule-set:douyin_domain': ['223.5.5.5', '119.29.29.29'],
    },

    // 全局境外上游：采用多提供商（Google / Cloudflare）DoH + DoT 并发，通过 "#一键代理" 经代理出站
    // 避免单一 DoH 服务器受到阻断或节点不稳定时导致境外 DNS 完全断流卡死
    'nameserver': [
      'https://dns.google/dns-query#一键代理',
      'https://1.1.1.1/dns-query#一键代理',
      'https://1.0.0.1/dns-query#一键代理',
      'https://8.8.8.8/dns-query#一键代理',
      'tls://8.8.8.8#一键代理'
    ]
  };

  // --- 4. 策略组 (Proxy Groups) ---
  // 优化顺序：将自动选路与故转组置前，避免默认选到无节点的手动/家宽组
  const commonProxies = [
    "一键代理",
    "香港自动", "日本自动", "新加坡自动", "美国自动", "台湾自动", "韩国自动", "欧洲自动",
    "香港故转", "日本故转", "新加坡故转", "美国故转", "台湾故转", "韩国故转", "欧洲故转",
    "香港手动", "日本手动", "新加坡手动", "美国手动", "台湾手动", "韩国手动", "欧洲手动",
    "全局均衡", "家宽节点", "其他手动"
  ];

  const specialProxies = [...commonProxies, "DIRECT"];
  const directFirstProxies = ["DIRECT", ...commonProxies];
  // Siri/Apple Intelligence 不提供 DIRECT，避免误选中国直连出口。
  const foreignProxies = [...commonProxies];

  const homeIcon = "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/05icon/home.png";
  const homeFilter = '^(?i)(?=.*(家宽|🏠|家庭宽带|宽带|住宅|民宅|\\bResidential\\b|\\bHome\\b|\\bISP\\b|Broadband)).*$';
  // 增强过滤无用占位/提示/公告节点，防止选到断流节点
  const excludeInfoFilter = '(?i)(群|返利|邀请|客服|工单|官网|网站|网址|邮箱|订阅|套餐|流量|到期|过期|剩余|重置|通知|更新|作者|频道|获取|下次|版本|官址|已用|联系|贩卖|倒卖|地址|说明|教程|关注|加入|建议|卡顿|专线|提示|公告|维护|测试|有效|http|expire|traffic|reset|subscription|remaining|used|total|email|panel|channel|author)';

  const aiProxies = ["家宽节点", "美国手动", ...commonProxies.filter(p => p !== "家宽节点" && p !== "美国手动")];

  config["proxy-groups"] = [
    {
      name: "一键代理",
      type: "select",
      proxies: commonProxies.filter(p => p !== "一键代理"),
      icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Rocket.png"
    },
    { name: "Streaming", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/YouTube.png" },
    { name: "GitHub", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/github(1).png" },
    { name: "Google", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Google_Search.png" },
    { name: "AI Services", type: "select", proxies: aiProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/AI.png" },
    { name: "Emby", type: "select", proxies: specialProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Emby.png" },
    { name: "Apple Intelligence", type: "select", proxies: foreignProxies, icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/Apple.png" },
    { name: "Apple", type: "select", proxies: directFirstProxies, icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/Apple.png" },
    { name: "Telegram", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Telegram.png" },
    { name: "WhatsApp", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/whatsapp.png" },
    { name: "Facebook", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Facebook.png" },
    { name: "Instagram", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Instagram.png" },
    { name: "Twitter", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Twitter.png" },
    { name: "TikTok", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/TikTok.png" },
    { name: "Microsoft", type: "select", proxies: directFirstProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Microsoft.png" },
    { name: "PayPal", type: "select", proxies: specialProxies, icon: "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/paypal(2).png" },
    { name: "Crypto", type: "select", proxies: specialProxies, icon: "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/Bitcoin.png" },
    { name: "Games", type: "select", proxies: specialProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Game.png" },
    { name: "VoWiFi", type: "select", proxies: ["欧洲手动", "美国手动", "其他手动"], icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/WiFi.png" },
    { name: "兜底流量", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Final.png" },

    // 区域自动/手动组
    // 地区词决定归属；IEPL / IPLC / BGP / Game / 倍率等线路标签不参与地区判断。
    // 没有明确地区词的节点进入“其他手动”，避免把线路标签误当成地区特征。
    {
      name: "全局均衡",
      type: "load-balance",
      strategy: "sticky-sessions",
      url: "https://www.gstatic.com/generate_204",
      interval: 300,
      lazy: true,
      timeout: 2000,
      "max-failed-times": 3,
      hidden: true,
      "include-all": true,
      "exclude-filter": excludeInfoFilter,
    },
    {
      name: "家宽节点",
      type: "select",
      "include-all": true,
      "exclude-filter": excludeInfoFilter,
      filter: homeFilter,
      icon: homeIcon
    },
    ...["香港", "日本", "台湾", "韩国", "新加坡", "美国", "欧洲"].map(region => {
      const iconMap = {
        "香港": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Hongkong(3).png",
        "台湾": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/taiwan(4).png",
        "日本": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Japan(2).png",
        "韩国": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Korea(2).png",
        "新加坡": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/singapore.png",
        "美国": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/US(2).png",
        "欧洲": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/EuropeanUnion(2).png",
      };
      const filterMap = {
        "香港": '^(?i)(?=.*(香港|🇭🇰|\\bHK\\b|Hong(?:\\s?Kong)?|\\bHKG\\b|\\bHKT\\b|\\bHKBN\\b)).*$',
        "台湾": '^(?i)(?=.*(台湾|台灣|🇹🇼|\\bTW\\b|\\bTPE\\b|\\bTSA\\b|\\bKHH\\b|Taiwan|Taipei|Kaohsiung)).*$',
        "日本": '^(?i)(?=.*(日本|🇯🇵|\\bJP\\b|Japan|Tokyo|Osaka|Fukuoka|\\bTYO\\b|\\bOSA\\b|\\bNRT\\b|\\bHND\\b|\\bKIX\\b|\\bCTS\\b|\\bFUK\\b)).*$',
        "韩国": '^(?i)(?=.*(韩国|韓國|🇰🇷|首尔|首爾|\\bKR\\b|\\bKOR\\b|Korea|Seoul|\\bSEL\\b|\\bICN\\b)).*$',
        "新加坡": '^(?i)(?=.*(新加坡|🇸🇬|\\bSG\\b|Singapore|\\bSGP\\b|\\bSIN\\b|\\bXSP\\b)).*$',
        "美国": '^(?i)(?=.*(美国|美國|🇺🇸|\\bUS\\b|\\bUSA\\b|\\bNA\\b|United\\s?States|America|\\bSJC\\b|\\bJFK\\b|\\bLAX\\b|\\bORD\\b|\\bATL\\b|\\bDFW\\b|\\bSFO\\b|\\bMIA\\b|\\bSEA\\b|\\bIAD\\b)).*$',
        "欧洲": '^(?i)(?=.*(奥地利|奥地利共和国|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|London|United\\s?Kingdom|England|Germany|France|Netherlands|Amsterdam|Frankfurt|Paris|\\bLON\\b|\\bUK\\b|\\bGB\\b|\\bGBR\\b|🇧🇪|🇨🇿|🇩🇰|🇫🇮|🇫🇷|🇩🇪|🇮🇪|🇮🇹|🇱🇹|🇱🇺|🇳🇱|🇵🇱|🇸🇪|🇬🇧|\\bCDG\\b|\\bFRA\\b|\\bAMS\\b|\\bMAD\\b|\\bBCN\\b|\\bFCO\\b|\\bMUC\\b|\\bBRU\\b|\\bLHR\\b|\\bLGW\\b)).*$'
      };
      return [
        {
          name: `${region}故转`,
          type: "fallback",
          url: "https://www.gstatic.com/generate_204",
          interval: 60,
          lazy: false,
          timeout: 2000,
          "max-failed-times": 1,
          proxies: [`${region}手动`, `${region}自动`],
          icon: iconMap[region],
          hidden: true
        },
        {
          name: `${region}手动`,
          type: "select",
          "include-all": true,
          "exclude-filter": excludeInfoFilter,
          filter: filterMap[region],
          icon: iconMap[region]
        },
        {
          name: `${region}自动`,
          type: "url-test",
          url: "https://www.gstatic.com/generate_204",
          interval: 120, // 从 300 秒降低到 120 秒，加快故障感知
          lazy: true,    // 仅在有网络请求时按需激活测试，降低空闲功耗
          tolerance: 50,
          timeout: 2000,
          "max-failed-times": 2, // 连续失败 2 次立即切换，不再傻等 15 分钟
          "include-all": true,
          "exclude-filter": excludeInfoFilter,
          filter: filterMap[region],
          icon: iconMap[region],
          hidden: true
        }
      ];
    }).flat(),
    {
      name: "其他手动",
      type: "select",
      "include-all": true,
      "exclude-filter": excludeInfoFilter,
      filter: '^(?i)(?!.*(DIRECT|直接连接|香港|台湾|台灣|日本|韩国|韓國|首尔|首爾|新加坡|美国|美國|奥地利|奥地利共和国|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|Hong(?:\\s?Kong)?|Taiwan|Taipei|Kaohsiung|Japan|Tokyo|Osaka|Fukuoka|Korea|Seoul|Singapore|United\\s?States|America|United\\s?Kingdom|England|London|Germany|France|Netherlands|Amsterdam|Frankfurt|Paris|🇭🇰|🇹🇼|🇸🇬|🇯🇵|🇰🇷|🇺🇸|🇬🇧|🇧🇪|🇨🇿|🇩🇰|🇫🇮|🇫🇷|🇩🇪|🇮🇪|🇮🇹|🇱🇹|🇱🇺|🇳🇱|🇵🇱|🇸🇪|\\bHK\\b|\\bHKG\\b|\\bHKT\\b|\\bHKBN\\b|\\bTW\\b|\\bTPE\\b|\\bTSA\\b|\\bKHH\\b|\\bJP\\b|\\bTYO\\b|\\bOSA\\b|\\bNRT\\b|\\bHND\\b|\\bKIX\\b|\\bCTS\\b|\\bFUK\\b|\\bKR\\b|\\bKOR\\b|\\bSEL\\b|\\bICN\\b|\\bSG\\b|\\bSGP\\b|\\bSIN\\b|\\bXSP\\b|\\bUS\\b|\\bUSA\\b|\\bNA\\b|\\bUK\\b|\\bGB\\b|\\bGBR\\b|\\bLON\\b|\\bSJC\\b|\\bJFK\\b|\\bLAX\\b|\\bORD\\b|\\bATL\\b|\\bDFW\\b|\\bSFO\\b|\\bMIA\\b|\\bSEA\\b|\\bIAD\\b|\\bCDG\\b|\\bFRA\\b|\\bAMS\\b|\\bMAD\\b|\\bBCN\\b|\\bFCO\\b|\\bMUC\\b|\\bBRU\\b|\\bLHR\\b|\\bLGW\\b)).*$',
      icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Global.png"
    }
  ];

  for (const group of config["proxy-groups"]) {
    if (group.type === "select" && Array.isArray(group.proxies)) {
      group["default-selected"] = group.proxies[0];
    }
    if (group["include-all"]) {
      group["exclude-type"] = "direct";
    }
    if (group.type === "fallback" || group.type === "url-test" || group.type === "load-balance") {
      group["empty-fallback"] = "REJECT";
      group["expected-status"] = 204;
    } else if (group.type === "select" && group["include-all"]) {
      group["empty-fallback"] = "REJECT";
    }
  }

  // --- 5. 规则集 (Rule Providers) ---
  config["rule-providers"] = {
    "fakeip_filter": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/fakeip-filter.mrs" },
    "ads_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://anti-ad.net/mihomo.mrs" },
    "private_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/private.mrs" },
    "speedtest_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/ookla-speedtest.mrs" },
    "ai": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-ai-!cn.mrs" },
    "github_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/github.mrs" },
    "youtube_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/youtube.mrs" },
    "instagram_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/rules/instagram_domain.mrs" },
    "twitch_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/rules/twitch_domain.mrs" },
    "twitch_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/rules/twitch_ip.mrs" },
    "google_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/google.mrs" },
    "telegram_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/telegram.mrs" },
    "line_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/rules/line_domain.mrs" },
    "line_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/rules/line_ip.mrs" },
    "whatsapp_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/rules/whatsapp_domain.mrs" },
    "whatsapp_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/rules/whatsapp_ip.mrs" },
    "douyin_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/douyin.mrs" },
    "tiktok_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/tiktok.mrs" },
    "twitter_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/twitter.mrs" },
    "netflix_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/netflix.mrs" },
    "disney_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/disney.mrs" },
    "spotify_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/spotify.mrs" },
    "crypto_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-cryptocurrency.mrs" },
    "paypal_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/paypal.mrs" },
    "finance_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-finance.mrs" },
    "games_cn_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-games@cn.mrs" },
    "games_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-games.mrs" },
    "microsoft_cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/microsoft@cn.mrs" },
    "apple_cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple@cn.mrs" },
    // 微软/苹果/其他
    "onedrive_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/onedrive.mrs" },
    "microsoft_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/microsoft.mrs" },
    "appletv_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple-tvplus.mrs" },
    "emby_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/666OS/rules@release/mihomo/domain/Emby.mrs" },
    "add_emby": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/Chunlion/Clash-Icons@main/Emby.mrs" },
    "vowifi": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/rules/UK-wifi-call.mrs" },
    "vowifi_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/rules/UK-wifi-call-ip.mrs" },
    "apple_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple.mrs" },
    // IP 规则
    "geolocation-!cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/geolocation-!cn.mrs" },
    "cn_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.mrs" },
    "add_direct_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/Seven1echo/Yaml@main/rules/Seven1_Direct_Domain.mrs" },
    "private_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/private.mrs" },
    "google_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/google.mrs" },
    "emby_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/666OS/rules@release/mihomo/ip/Emby.mrs" },
    "telegram_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/telegram.mrs" },
    "twitter_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/twitter.mrs" },
    "netflix_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/netflix.mrs" },
    "cn_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs" }
  };

  for (const provider of Object.values(config["rule-providers"])) {
    if (provider.type === "http") {
      provider["size-limit"] = 8 * 1024 * 1024;
      provider.proxy = "一键代理";
    }
  }

  // --- 6. 规则匹配 (Rules) ---
  config["rules"] = [
    "AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((OR,((RULE-SET,cn_domain),(RULE-SET,private_domain),(RULE-SET,private_ip),(RULE-SET,cn_ip)))))),REJECT",
    // DoT（TCP 853）：硬编码 DNS 的应用也必须走代理，防止直连境外出站暴露查询目标
    "AND,((NETWORK,TCP),(DST-PORT,853)),一键代理",
    "RULE-SET,ads_domain,REJECT",
    "RULE-SET,private_domain,DIRECT",
    "RULE-SET,private_ip,DIRECT,no-resolve",
    "DOMAIN-SUFFIX,3gppnetwork.org,VoWiFi",
    "AND,((NETWORK,UDP),(DST-PORT,500)),VoWiFi",
    "AND,((NETWORK,UDP),(DST-PORT,4500)),VoWiFi",
    "RULE-SET,vowifi,VoWiFi",
    "RULE-SET,vowifi_ip,VoWiFi,no-resolve",
    "RULE-SET,microsoft_cn,DIRECT",

    // Siri 关键词：覆盖未列出的 Siri 子域名，强制走 Apple Intelligence 代理组。
    "DOMAIN-KEYWORD,siri,Apple Intelligence",
    ...appleIntelligenceDomainRules.map(domain => `DOMAIN,${domain},Apple Intelligence`),
    ...appleIntelligenceSuffixRules.map(domain => `DOMAIN-SUFFIX,${domain},Apple Intelligence`),
    "RULE-SET,apple_cn,DIRECT",
    "RULE-SET,speedtest_domain,DIRECT",

    // Meta Muse is a separate personal AI agent at muse.ai. Put its
    // canonical web domain before the generic AI category so it is routed to
    // AI Services even if a future upstream category-ai-!cn update omits it.
    "DOMAIN,muse.ai,AI Services",
    "DOMAIN-SUFFIX,muse.ai,AI Services",
    "DOMAIN,ai.meta.com,AI Services",
    "DOMAIN-SUFFIX,meta.ai,AI Services",
    "RULE-SET,ai,AI Services",
    "RULE-SET,github_domain,GitHub",
    "RULE-SET,youtube_domain,Streaming",
    "RULE-SET,twitch_domain,Streaming",
    "RULE-SET,twitch_ip,Streaming,no-resolve",
    "RULE-SET,google_domain,Google",
    "RULE-SET,games_cn_domain,DIRECT",
    "RULE-SET,games_domain,Games",
    "RULE-SET,onedrive_domain,Microsoft",
    "RULE-SET,microsoft_domain,Microsoft",
    "RULE-SET,appletv_domain,Streaming",
    "RULE-SET,emby_domain,Emby",
    "RULE-SET,apple_domain,Apple",
    "RULE-SET,telegram_domain,Telegram",
    "RULE-SET,line_domain,Telegram",
    "RULE-SET,line_ip,Telegram,no-resolve",
    // 2026-09-27 实测: WhatsApp App 实际使用 whatsapp.net 系域名,Chunlion 的 whatsapp_domain
    // 规则集未收录,导致流量掉进 geolocation-!cn 走一键代理。显式置顶修复。
    "DOMAIN-SUFFIX,whatsapp.net,WhatsApp",
    "RULE-SET,whatsapp_domain,WhatsApp",
    "RULE-SET,whatsapp_ip,WhatsApp,no-resolve",
    "GEOSITE,facebook,Facebook",
    "GEOIP,facebook,Facebook,no-resolve",
    "RULE-SET,instagram_domain,Instagram",
    "RULE-SET,douyin_domain,DIRECT",
    "RULE-SET,tiktok_domain,TikTok",
    "RULE-SET,twitter_domain,Twitter",
    "RULE-SET,netflix_domain,Streaming",
    "RULE-SET,disney_domain,Streaming",
    "RULE-SET,spotify_domain,Streaming",
    "RULE-SET,crypto_domain,Crypto",
    "RULE-SET,paypal_domain,PayPal",
    "RULE-SET,finance_domain,PayPal",
    "RULE-SET,add_emby,Emby",
    "RULE-SET,add_direct_domain,DIRECT",
    "RULE-SET,emby_ip,Emby,no-resolve",
    "RULE-SET,google_ip,Google,no-resolve",
    "RULE-SET,telegram_ip,Telegram,no-resolve",
    "RULE-SET,twitter_ip,Twitter,no-resolve",
    "RULE-SET,netflix_ip,Streaming,no-resolve",
    // 2026-09-27 日志实证: 客户端曾把 browserleaks.com 误判进 RuleSet(cn_domain) 走 DIRECT
    // (上游 cn.mrs 并无该域名,疑似客户端规则集缓存过期)。显式置顶,确保检测站走代理。
    "DOMAIN-SUFFIX,browserleaks.com,一键代理",
    "RULE-SET,cn_domain,DIRECT",
    "RULE-SET,cn_ip,DIRECT,no-resolve",
    "RULE-SET,geolocation-!cn,一键代理",
    "MATCH,兜底流量"
  ];

  return config;
}
