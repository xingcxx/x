function main(config) {

  // ================================================================
  // Clash Mi / Mihomo Perfect-Rules v1.7
  //
  // Architecture:
  //
  //   Airport Subscription
  //          ↓
  //   Preserve Airport Basic Groups
  //          ↓
  //   Dynamic Region Groups
  //          ↓
  //   Perfect-Rules Service Groups
  //          ↓
  //   Remote Rule Providers
  //
  // JS:
  //   Responsible for configuration architecture
  //
  // GitHub Rule Providers:
  //   Responsible for actual routing rules
  //
  // Network Test:
  //   Follow airport's default manual selector
  //
  // ================================================================


  // ================================================================
  // 1. Basic configuration
  // ================================================================

  config["mixed-port"] = 7890;

  config["mode"] = "rule";

  config["unified-delay"] = true;

  config["tcp-concurrent"] = true;

  config["log-level"] = "error";

  // Avoid advertising native IPv6 to applications.  On iOS, the VPN
  // extension owns the TUN routes; the core does not need a custom IPv6 TUN
  // address for Fake-IP DNS interception.
  config["ipv6"] = false;

  config["allow-lan"] = false;

  config["find-process-mode"] = "always";

  config["keep-alive-interval"] = 30;

  config["keep-alive-idle"] = 30;

  config["disable-keep-alive"] = false;


  // ================================================================
  // 2. Profile
  // ================================================================

  config["profile"] = {

    "store-selected": true,

    "store-fake-ip": true

  };


  // ================================================================
  // 3. DNS
  //
  // All upstream DNS uses DoH/DoT.  `respect-rules` makes the DNS
  // connection itself follow this profile's routing rules; the sole
  // unavoidable bootstrap path (proxy host names) is also encrypted.
  // ================================================================

  config["dns"] = {

    "enable": true,

    "listen": "0.0.0.0:53",

    "prefer-h3": false,

    "ipv6": false,

    "enhanced-mode": "fake-ip",

    "fake-ip-range": "198.18.0.1/16",

    "fake-ip-filter": [

      "+.lan",
      "+.local",
      "+.localhost",
      "+.home.arpa",

      // The Mac SSH endpoint resolves to a private LAN address.  It must
      // retain its real address rather than receive a Fake-IP mapping.
      "mac.024657.xyz",

      "time.*.com",
      "time.*.gov",
      "pool.ntp.org",

      "+.push.apple.com",

      "mesu.apple.com",
      "swscan.apple.com",

      "captive.apple.com",

      "connectivitycheck.gstatic.com",

      "connectivitycheck.android.com",

      "www.msftconnecttest.com",

      "www.msftncsi.com"

    ],

    // Resolve DNS-server and proxy-server host names without sending
    // plaintext UDP/53 traffic.  These are numeric IP endpoints so no
    // system DNS lookup is needed before the profile is available.
    "default-nameserver": [

      "tls://223.5.5.5:853",
      "tls://1.12.12.12:853"

    ],

    // Imported Clash Mi profiles support this setting.  Global DoH
    // queries follow the normal routing rules and therefore the final proxy
    // group, while the explicit CN/private policy remains direct below.
    "respect-rules": true,

    // Do not use fallback: it duplicates queries to a second resolver
    // and can disclose a domain to the wrong DNS path.
    "nameserver": [

      "https://1.1.1.1/dns-query",
      "https://9.9.9.9/dns-query"

    ],

    "nameserver-policy": {

      // Resolve the Mac SSH name with the direct encrypted resolvers.  Clash Mi
      // does not consistently expose the iOS `system` resolver to TUN clients;
      // using the same dynamic public record avoids an `unknown host` result.
      "mac.024657.xyz": [

        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"

      ],

      "geosite:cn,private": [

        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"

      ],

      "geosite:geolocation-!cn": [

        "https://1.1.1.1/dns-query",
        "https://9.9.9.9/dns-query"

      ]

    },

    // A proxy endpoint must be resolved before its proxy can connect.
    // Keep that bootstrap query encrypted and independent of system DNS.
    "proxy-server-nameserver": [

      "tls://223.5.5.5:853",
      "tls://1.12.12.12:853"

    ],

    // A dedicated encrypted resolver for direct traffic is compatible with
    // split-DNS.  `follow-policy` keeps CN/private policy above authoritative.
    "direct-nameserver": [

      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"

    ],

    "direct-nameserver-follow-policy": true

  };


  // ================================================================
  // 4. TUN
  // ================================================================

  config["tun"] = {

    "enable": true,

    "device": "Clash Mi",

    // Mixed is the portable Mihomo TUN stack used by no-leak
    // overwrite profiles; it avoids the iOS route loop caused by manually
    // supplied route-address entries.
    "stack": "mixed",

    // Catch UDP and TCP DNS from every interface.  A single IPv4 UDP
    // entry leaves TCP DNS and IPv6-interface DNS able to bypass TUN.
    "dns-hijack": [

      "any:53",
      "tcp://any:53"

    ],

    "auto-route": true,

    // When both Wi-Fi and cellular are available, select the physical egress
    // automatically. Do not add custom route-address entries on Apple.
    "auto-detect-interface": true,

    // iOS installs VPN routes itself.  Enabling strict-route or
    // manually specifying IPv4/IPv6 routes here can send the tunnel's own
    // transport back into TUN and cause a reconnect loop.
    "strict-route": false,

    "endpoint-independent-nat": true,

    "mtu": 1500,

    "auto-redirect": false,

    "disable-icmp-forwarding": true

  };


  // ================================================================
  // 5. Sniffer
  // ================================================================

  config["sniffer"] = {

    "enable": true,

    "parse-pure-ip": true,

    "force-dns-mapping": true,

    "override-destination": true,

    "sniff": {

      "HTTP": {

        "ports": [

          80,
          "8080-8880"

        ]

      },

      "TLS": {

        "ports": [

          443,
          8443

        ]

      },

      "QUIC": {

        "ports": [

          443,
          8443

        ]

      }

    },

    "skip-domain": [

      "+.push.apple.com",
      "+.mijia.cloud"

    ]

  };


  // ================================================================
  // 6. NTP
  // ================================================================

  config["ntp"] = {

    "enable": true,

    "write-to-system": false,

    "server": "time.apple.com",

    "port": 123,

    "interval": 30

  };


  // ================================================================
  // 7. Original airport proxies
  // ================================================================

  var originalProxies = Array.isArray(config["proxies"])
    ? config["proxies"]
    : [];


  var proxyNames = [];

  originalProxies.forEach(function(proxy) {

    if (proxy && proxy.name) {

      proxyNames.push(proxy.name);

    }

  });


  // ================================================================
  // 8. Original airport proxy groups
  // ================================================================

  var originalGroups = Array.isArray(config["proxy-groups"])
    ? config["proxy-groups"]
    : [];


  // ================================================================
  // 9. Perfect-Rules icon CDN
  // ================================================================

  var iconBaseURL =
    "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/icons/";


  var groupIcons = {

    "一键代理": "Proxy.png",

    "国内直连": "China.png",

    "AI": "AI.png",

    "YouTube": "YouTube.png",

    "Google": "Google.png",

    "GitHub": "GitHub.png",

    "网络检测": "Network-test.png",

    "Netflix": "Netflix.png",

    "Spotify": "Spotify.png",

    "Steam": "Steam.png",

    "Telegram": "Telegram.png",

    "TikTok": "TikTok.png",

    "Apple": "Apple.png",

    "Microsoft": "Microsoft.png",

    "香港": "Hong_Kong.png",

    "台湾": "Taiwan.png",

    "日本": "Japan.png",

    "新加坡": "Singapore.png",

    "韩国": "Korea.png",

    "美国": "United_States.png",

    "加拿大": "Other.png",

    "英国": "Other.png",

    "其他地区": "Other.png"

  };


  function getGroupIcon(name) {

    if (!groupIcons[name]) {

      return undefined;

    }

    return iconBaseURL + groupIcons[name];

  }


  // ================================================================
  // 10. Managed groups
  // ================================================================

  var managedGroups = {

    "一键代理": true,

    "国内直连": true,

    "AI": true,

    "YouTube": true,

    "Google": true,

    "GitHub": true,

    "网络检测": true,

    "Netflix": true,

    "Spotify": true,

    "Steam": true,

    "Telegram": true,

    "TikTok": true,

    "Apple": true,

    "Microsoft": true,

    "香港": true,

    "台湾": true,

    "日本": true,

    "新加坡": true,

    "韩国": true,

    "美国": true,

    "加拿大": true,

    "英国": true,

    "其他地区": true

  };


  // ================================================================
  // 11. Built-in targets
  // ================================================================

  var builtinTargets = {

    "DIRECT": true,

    "REJECT": true,

    "REJECT-DROP": true,

    "PASS": true,

    "COMPATIBLE": true,

    "GLOBAL": true

  };


  // ================================================================
  // 12. Business group detection
  // ================================================================

  function isBusinessGroupName(name) {

    if (!name) {

      return false;

    }

    var text = String(name);


    var patterns = [

      /ai/i,

      /openai/i,

      /chatgpt/i,

      /claude/i,

      /gemini/i,

      /netflix/i,

      /disney/i,

      /disney\+/i,

      /youtube/i,

      /google/i,

      /github/i,

      /spotify/i,

      /steam/i,

      /tiktok/i,

      /telegram/i,

      /twitter/i,

      /x\.com/i,

      /facebook/i,

      /instagram/i,

      /流媒体/i,

      /媒体/i,

      /影音/i,

      /视频/i,

      /游戏/i,

      /游戏专用/i,

      /机场专用/i,

      /节点分流/i

    ];


    for (var i = 0; i < patterns.length; i++) {

      if (patterns[i].test(text)) {

        return true;

      }

    }


    return false;

  }


  // ================================================================
  // 13. Auto-select detection
  // ================================================================

  function isAutoSelectGroup(name) {

    if (!name) {

      return false;

    }


    return (

      /自动选择/i.test(name) ||

      /auto[\s_-]*select/i.test(name) ||

      /auto[\s_-]*test/i.test(name) ||

      /测速/i.test(name)

    );

  }


  // ================================================================
  // 14. Failover detection
  // ================================================================

  function isFailoverGroup(name) {

    if (!name) {

      return false;

    }


    return (

      /故障转移/i.test(name) ||

      /failover/i.test(name) ||

      /fallback/i.test(name)

    );

  }


  // ================================================================
  // 15. All-node detection
  // ================================================================

  function isAllNodeName(name) {

    if (!name) {

      return false;

    }


    return (

      /全部节点/i.test(name) ||

      /所有节点/i.test(name) ||

      /全部/i.test(name) ||

      /all[\s_-]*nodes?/i.test(name) ||

      /all[\s_-]*proxies?/i.test(name)

    );

  }


  function getProxyComposition(group) {

    var result = {

      total: 0,

      actualNodes: 0,

      groups: 0,

      builtin: 0,

      unknown: 0

    };


    if (

      !group ||

      !Array.isArray(group.proxies)

    ) {

      return result;

    }


    result.total =
      group.proxies.length;


    group.proxies.forEach(function(item) {

      if (!item) {

        return;

      }


      if (proxyNames.indexOf(item) !== -1) {

        result.actualNodes++;

        return;

      }


      if (builtinTargets[item]) {

        result.builtin++;

        return;

      }


      var referencedGroup =
        originalGroups.some(function(g) {

          return (

            g &&

            g.name === item

          );

        });


      if (referencedGroup) {

        result.groups++;

        return;

      }


      result.unknown++;

    });


    return result;

  }


  function isAllNodesGroup(group) {

    if (!group || !group.name) {

      return false;

    }


    var name =
      String(group.name);


    if (isAllNodeName(name)) {

      return true;

    }


    if (isBusinessGroupName(name)) {

      return false;

    }


    var composition =
      getProxyComposition(group);


    if (composition.total === 0) {

      return false;

    }


    if (composition.actualNodes < 2) {

      return false;

    }


    var ratio =
      composition.actualNodes /
      composition.total;


    if (ratio < 0.3) {

      return false;

    }


    if (composition.groups > 0) {

      if (composition.actualNodes >= 5) {

        return true;

      }

      return false;

    }


    return true;

  }


  // ================================================================
  // 16. Preserve airport basic groups
  //
  // IMPORTANT:
  //
  // v1.5.1 fixed the problem where "九云" disappeared.
  //
  // Never force hidden=true.
  // ================================================================

  var preservedGroups = [];


  originalGroups.forEach(function(group) {

    if (!group || !group.name) {

      return;

    }


    if (managedGroups[group.name]) {

      return;

    }


    var isBasic =

      isAutoSelectGroup(group.name) ||

      isFailoverGroup(group.name) ||

      isAllNodesGroup(group);


    if (!isBasic) {

      return;

    }


    var copied =
      JSON.parse(JSON.stringify(group));


    // Keep airport group visible.

    delete copied["hidden"];


    preservedGroups.push(copied);

  });


  // ================================================================
  // 17. Convert airport Auto-Select groups to URL-Test
  // ================================================================

  preservedGroups.forEach(function(group) {

    if (!group || !group.name) {

      return;

    }


    if (!isAutoSelectGroup(group.name)) {

      return;

    }


    group.type = "url-test";


    group.proxies =
      proxyNames.slice();


    group.url =
      "https://www.gstatic.com/generate_204";


    group.interval = 300;


    group.timeout = 5000;


    group.tolerance = 50;


    group.lazy = true;


    group["max-failed-times"] = 3;


    group["expected-status"] = 204;


    delete group["disable-udp"];

    delete group["strategy"];

  });


  // ================================================================
  // 18. Find airport default manual selector
  //
  // Purpose:
  //
  //   Network Test
  //       ↓
  //   Airport Default Selector
  //       ↓
  //   User-selected node
  //
  // Example:
  //
  //   网络检测
  //       ↓
  //      九云
  //       ↓
  //      台湾节点
  //
  // Do NOT hardcode "九云".
  // ================================================================

  function findDefaultAirportGroup() {

    var candidates = [];


    originalGroups.forEach(function(group) {

      if (!group || !group.name) {

        return;

      }


      var name =
        String(group.name);


      // Ignore groups managed by Perfect-Rules.

      if (managedGroups[name]) {

        return;

      }


      // Ignore automatic groups.

      if (isAutoSelectGroup(name)) {

        return;

      }


      // Ignore failover groups.

      if (isFailoverGroup(name)) {

        return;

      }


      // Ignore obvious business groups.

      if (isBusinessGroupName(name)) {

        return;

      }


      if (group.type !== "select") {

        return;

      }


      var composition =
        getProxyComposition(group);


      if (composition.actualNodes < 2) {

        return;

      }


      candidates.push({

        group: group,

        score: 0,

        index: candidates.length

      });

    });


    // --------------------------------------------------------------
    // Prefer an all-node manual selector.
    //
    // This matches common airport structures such as:
    //
    //   九云
    //   节点
    //   全部节点
    //
    // where the group directly contains many actual proxy nodes.
    // --------------------------------------------------------------

    for (var i = 0; i < candidates.length; i++) {

      if (isAllNodesGroup(candidates[i].group)) {

        return candidates[i].group.name;

      }

    }


    // --------------------------------------------------------------
    // Fallback:
    //
    // Use the first suitable manual select group.
    // --------------------------------------------------------------

    if (candidates.length > 0) {

      return candidates[0].group.name;

    }


    return null;

  }


  var defaultAirportGroup =
    findDefaultAirportGroup();


  // ================================================================
  // 19. Remote Rule Provider base URL
  // ================================================================

  var ruleBaseURL =
    "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/rules/";


  // ================================================================
  // 20. Rule Provider factory
  // ================================================================

  function createRuleProvider(filename) {

    return {

      "type": "http",

      "behavior": "classical",

      "format": "yaml",

      "url": ruleBaseURL + filename,

      "path": "./rules/" + filename,

      "interval": 86400

    };

  }


  // ================================================================
  // 21. Remote Rule Providers
  //
  // GitHub repository:
  //
  // n0de-sudo/Perfect-Rules
  //
  // ================================================================

  config["rule-providers"] = {

    "AI":
      createRuleProvider("ai.yaml"),

    "YouTube":
      createRuleProvider("youtube.yaml"),

    "Google":
      createRuleProvider("google.yaml"),

    "GitHub":
      createRuleProvider("github.yaml"),

    "Netflix":
      createRuleProvider("netflix.yaml"),

    "Spotify":
      createRuleProvider("spotify.yaml"),

    "Steam":
      createRuleProvider("steam.yaml"),

    "Telegram":
      createRuleProvider("telegram.yaml"),

    "TikTok":
      createRuleProvider("tiktok.yaml"),

    "Apple":
      createRuleProvider("apple.yaml"),

    "Microsoft":
      createRuleProvider("microsoft.yaml"),

    "NetworkTest":
      createRuleProvider("network-test.yaml")

  };


  // ================================================================
  // 22. Region detection
  // ================================================================

  var regionPatterns = {

    "香港": [

      /香港/i,

      /\bHK\b/i,

      /HKG/i,

      /Hong\s*Kong/i,

      /HongKong/i

    ],


    "台湾": [

      /台湾/i,

      /台灣/i,

      /\bTW\b/i,

      /TPE/i,

      /KHH/i,

      /TSA/i,

      /Taiwan/i,

      /Taipei/i

    ],


    "日本": [

      /日本/i,

      /\bJP\b/i,

      /NRT/i,

      /HND/i,

      /KIX/i,

      /CTS/i,

      /FUK/i,

      /Japan/i,

      /Tokyo/i,

      /Osaka/i

    ],


    "新加坡": [

      /新加坡/i,

      /\bSG\b/i,

      /SIN/i,

      /XSP/i,

      /Singapore/i

    ],


    "韩国": [

      /韩国/i,

      /韓國/i,

      /\bKR\b/i,

      /ICN/i,

      /GMP/i,

      /PUS/i,

      /Korea/i,

      /Seoul/i

    ],


    "美国": [

      /美国/i,

      /\bUS\b/i,

      /\bUSA\b/i,

      /LAX/i,

      /SFO/i,

      /JFK/i,

      /SJC/i,

      /United\s*States/i,

      /America/i,

      /Los\s*Angeles/i,

      /San\s*Jose/i,

      /New\s*York/i

    ],


    "加拿大": [

      /加拿大/i,

      /Canada/i,

      /Toronto/i,

      /Vancouver/i,

      /Montreal/i

    ],


    "英国": [

      /英国/i,

      /UK/i,

      /United\s*Kingdom/i,

      /England/i,

      /London/i,

      /Manchester/i

    ]

  };


  function detectRegion(proxyName) {

    for (var region in regionPatterns) {

      if (!regionPatterns.hasOwnProperty(region)) {

        continue;

      }


      var patterns =
        regionPatterns[region];


      for (var i = 0; i < patterns.length; i++) {

        if (patterns[i].test(proxyName)) {

          return region;

        }

      }

    }


    return "其他地区";

  }


  // ================================================================
  // 23. Build region node lists
  // ================================================================

  var regionNodes = {

    "香港": [],

    "台湾": [],

    "日本": [],

    "新加坡": [],

    "韩国": [],

    "美国": [],

    "加拿大": [],

    "英国": [],

    "其他地区": []

  };


  originalProxies.forEach(function(proxy) {

    if (!proxy || !proxy.name) {

      return;

    }


    var region =
      detectRegion(String(proxy.name));


    regionNodes[region].push(

      proxy.name

    );

  });


  // ================================================================
  // 24. Region order
  // ================================================================

  var regionOrder = [

    "香港",

    "台湾",

    "日本",

    "新加坡",

    "韩国",

    "美国",

    "加拿大",

    "英国",

    "其他地区"

  ];


  // ================================================================
  // 25. Create region URL-Test groups
  // ================================================================

  var regionGroups = [];


  regionOrder.forEach(function(region) {

    var nodes =
      regionNodes[region];


    if (

      !nodes ||

      nodes.length === 0

    ) {

      return;

    }


    var group = {

      "name": region,

      "type": "url-test",

      "proxies": nodes,

      "url":
        "https://www.gstatic.com/generate_204",

      "interval": 300,

      "timeout": 5000,

      "tolerance": 50,

      "lazy": true,

      "max-failed-times": 3,

      "expected-status": 204

    };


    var icon =
      getGroupIcon(region);


    if (icon) {

      group["icon"] = icon;

    }


    regionGroups.push(group);

  });


  var availableRegions =
    regionGroups.map(function(group) {

      return group.name;

    });


  // ================================================================
  // 26. Domestic Direct
  // ================================================================

  var domesticDirectGroup = {

    "name": "国内直连",

    "type": "select",

    "proxies": [

      "DIRECT"

    ]

  };


  var domesticIcon =
    getGroupIcon("国内直连");


  if (domesticIcon) {

    domesticDirectGroup["icon"] =
      domesticIcon;

  }


  // ================================================================
  // 27. One-click Proxy
  // ================================================================

  var mainSelector = {

    "name": "一键代理",

    "type": "select",

    "proxies":
      availableRegions.concat([

        "国内直连"

      ])

  };


  var mainIcon =
    getGroupIcon("一键代理");


  if (mainIcon) {

    mainSelector["icon"] =
      mainIcon;

  }


  // ================================================================
  // 28. Service groups
  // ================================================================

  function createBusinessGroup(name) {

    var group = {

      "name": name,

      "type": "select",

      "proxies":
        availableRegions.concat([

          "国内直连"

        ])

    };


    var icon =
      getGroupIcon(name);


    if (icon) {

      group["icon"] = icon;

    }


    return group;

  }


  var businessGroups = [

    createBusinessGroup("AI"),

    createBusinessGroup("YouTube"),

    createBusinessGroup("Google"),

    createBusinessGroup("GitHub"),

    createBusinessGroup("Netflix"),

    createBusinessGroup("Spotify"),

    createBusinessGroup("Steam"),

    createBusinessGroup("Telegram"),

    createBusinessGroup("TikTok"),

    createBusinessGroup("Apple"),

    createBusinessGroup("Microsoft")

  ];


  // ================================================================
  // 29. Network Test
  //
  // IMPORTANT:
  //
  // Network Test follows the airport's default manual selector.
  //
  // Example:
  //
  //   九云
  //      ↓
  //   台湾节点
  //
  // Network Test:
  //
  //   网络检测
  //      ↓
  //     九云
  //      ↓
  //   台湾节点
  //
  // Therefore the network diagnostic websites will test the same
  // outbound proxy selected by the user in the airport's default
  // manual selector.
  //
  // ================================================================

  var networkTestGroup = {

    "name": "网络检测",

    "type": "select",

    "proxies": []

  };


  if (defaultAirportGroup) {

    networkTestGroup["proxies"] = [

      defaultAirportGroup

    ];

  } else {

    // Fallback:
    //
    // If no suitable airport manual selector can be detected,
    // follow the Perfect-Rules main selector instead.

    networkTestGroup["proxies"] = [

      "一键代理"

    ];

  }


  var networkTestIcon =
    getGroupIcon("网络检测");


  if (networkTestIcon) {

    networkTestGroup["icon"] =
      networkTestIcon;

  }


  // ================================================================
  // 30. Final proxy-group list
  //
  // IMPORTANT:
  //
  // Airport groups are preserved.
  //
  // Example:
  //
  //   九云
  //
  // remains visible.
  //
  // Network Test follows the airport default selector.
  //
  // ================================================================

  config["proxy-groups"] =

    preservedGroups

      .concat(businessGroups)

      .concat([

        networkTestGroup

      ])

      .concat(regionGroups)

      .concat([

        domesticDirectGroup,

        mainSelector

      ]);


  // ================================================================
  // 31. Routing rules
  //
  // IMPORTANT:
  //
  // Rule Providers are deliberately ordered:
  //
  // NetworkTest
  // AI
  // YouTube
  // Google
  // GitHub
  // Netflix
  // Spotify
  // Steam
  // Telegram
  // TikTok
  // Apple
  // Microsoft
  // CN / Private
  // MATCH
  //
  // YouTube MUST be before Google.
  //
  // ================================================================

  config["rules"] = [

    // --------------------------------------------------------------
    // Private / LAN
    // --------------------------------------------------------------

    // Shadowrocket uses an exact direct rule plus `server:system` for this
    // private-LAN SSH hostname.  Keep this before the 024657 proxy suffix.
    "DOMAIN,mac.024657.xyz,DIRECT",

    "DOMAIN-SUFFIX,024657.xyz,一键代理",

    "DOMAIN-SUFFIX,lan,DIRECT",

    "DOMAIN-SUFFIX,local,DIRECT",

    "DOMAIN-SUFFIX,localhost,DIRECT",

    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",

    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",

    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",

    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",


    // --------------------------------------------------------------
    // Network Test
    // --------------------------------------------------------------

    "RULE-SET,NetworkTest,网络检测",


    // --------------------------------------------------------------
    // AI
    // --------------------------------------------------------------

    "RULE-SET,AI,AI",


    // --------------------------------------------------------------
    // YouTube
    //
    // MUST be before Google.
    // --------------------------------------------------------------

    "RULE-SET,YouTube,YouTube",


    // --------------------------------------------------------------
    // Google
    // --------------------------------------------------------------

    "RULE-SET,Google,Google",


    // --------------------------------------------------------------
    // GitHub
    // --------------------------------------------------------------

    "RULE-SET,GitHub,GitHub",


    // --------------------------------------------------------------
    // Netflix
    // --------------------------------------------------------------

    "RULE-SET,Netflix,Netflix",


    // --------------------------------------------------------------
    // Spotify
    // --------------------------------------------------------------

    "RULE-SET,Spotify,Spotify",


    // --------------------------------------------------------------
    // Steam
    // --------------------------------------------------------------

    "RULE-SET,Steam,Steam",


    // --------------------------------------------------------------
    // Telegram
    // --------------------------------------------------------------

    "RULE-SET,Telegram,Telegram",


    // --------------------------------------------------------------
    // TikTok
    // --------------------------------------------------------------

    "RULE-SET,TikTok,TikTok",


    // --------------------------------------------------------------
    // Apple
    // --------------------------------------------------------------

    "RULE-SET,Apple,Apple",


    // --------------------------------------------------------------
    // Microsoft
    // --------------------------------------------------------------

    "RULE-SET,Microsoft,Microsoft",


    // --------------------------------------------------------------
    // Private
    // --------------------------------------------------------------

    "GEOSITE,private,国内直连",

    "GEOIP,private,国内直连,no-resolve",


    // --------------------------------------------------------------
    // China
    // --------------------------------------------------------------

    "GEOSITE,cn,国内直连",

    "GEOIP,cn,国内直连,no-resolve",


    // --------------------------------------------------------------
    // Final
    // --------------------------------------------------------------

    "MATCH,一键代理"

  ];


  // ================================================================
  // 32. Return generated config
  // ================================================================

  return config;

}
