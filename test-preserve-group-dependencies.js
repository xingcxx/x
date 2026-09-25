// The generated config must retain an airport selector dependency chain.
// Regression fixture: 日本专线 -> 日本节点 -> three newly-added Japan proxies.
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync('clash.js', 'utf8');
const sandbox = {};
vm.runInNewContext(source, sandbox);
const main = sandbox.main;

const config = {
  proxies: [
    { name: '日本 01' },
    { name: '日本 02' },
    { name: '日本 03' }
  ],
  'proxy-groups': [
    {
      name: '总选择',
      type: 'select',
      proxies: ['日本专线', '日本 01', '日本 02', '日本 03']
    },
    {
      name: '日本专线',
      type: 'select',
      proxies: ['日本节点']
    },
    {
      name: '日本节点',
      type: 'url-test',
      proxies: ['日本 01', '日本 02', '日本 03']
    }
  ]
};

main(config);
const groups = config['proxy-groups'];
const names = new Set(groups.map(group => group.name));
const japanDedicated = groups.find(group => group.name === '日本专线');
const japanNodes = groups.find(group => group.name === '日本节点');

if (!japanDedicated || !japanNodes) {
  throw new Error(`Missing required airport groups: ${JSON.stringify([...names])}`);
}
if (!japanDedicated.proxies.includes('日本节点')) {
  throw new Error('日本专线 no longer references 日本节点');
}
for (const group of groups) {
  for (const item of group.proxies || []) {
    const builtin = ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL'];
    const node = config.proxies.some(proxy => proxy.name === item);
    if (!builtin.includes(item) && !node && !names.has(item)) {
      throw new Error(`Dangling proxy-group reference: ${group.name} -> ${item}`);
    }
  }
}
console.log('PASS: 日本专线 and 日本节点 retained; no dangling group references');
