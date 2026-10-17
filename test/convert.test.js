import test from 'node:test';
import assert from 'node:assert/strict';
import { convertSubscription } from '../src/convert.js';
import { fetchSubscription, validateSourceUrl } from '../src/fetch-source.js';

function vmessLink(name = 'VMess WebSocket') {
  const payload = {
    add: 'vm.example.net',
    port: '443',
    id: '11111111-2222-4333-8444-555555555555',
    aid: '0',
    net: 'ws',
    host: 'cdn.example.net',
    path: '/tunnel',
    tls: 'tls',
    ps: name,
  };
  return `vmess://${Buffer.from(JSON.stringify(payload)).toString('base64')}`;
}

test('converts supported share links and reports protocols Surge cannot use', () => {
  const input = [
    vmessLink(),
    'trojan://p%40ss@edge.example.net:443?sni=front.example.net&type=ws&host=front.example.net&path=%2Fconnect#Trojan%20TLS',
    'hysteria2://secret@udp.example.net:8443?sni=udp.example.net&obfs=salamander&obfs-password=veil#Fast%20UDP',
    'vless://11111111-2222-4333-8444-555555555555@vless.example.net:443?security=tls#Not%20Supported',
    'ssr://c29tZS1ub2Rl',
  ].join('\n');

  const result = convertSubscription(input);
  assert.equal(result.total, 5);
  assert.equal(result.converted, 3);
  assert.equal(result.skipped, 2);
  assert.deepEqual(result.skippedByProtocol, { vless: 1, ssr: 1 });
  assert.match(result.config, /VMess WebSocket = vmess, vm\.example\.net, 443/);
  assert.match(result.config, /username=11111111-2222-4333-8444-555555555555/);
  assert.match(result.config, /ws-path=\/tunnel/);
  assert.match(result.config, /Trojan TLS = trojan, edge\.example\.net, 443, password=p@ss/);
  assert.match(result.config, /Fast UDP = hysteria2, udp\.example\.net, 8443/);
  assert.match(result.config, /salamander-password=veil/);
  assert.doesNotMatch(result.config, /vless|ssr/i);
  assert.match(result.fullConfig, /^\[General\]\nloglevel = notify/m);
  assert.match(result.fullConfig, /\[Proxy\]\nVMess WebSocket = vmess/);
  assert.match(result.fullConfig, /\[Proxy Group\]\nProxy = select, VMess WebSocket, Trojan TLS, Fast UDP, DIRECT/);
  assert.match(result.fullConfig, /\[Rule\]\nFINAL, Proxy/);
});

test('decodes a Base64 Shadowsocks subscription and supports SIP002 credentials', () => {
  const link = 'ss://aes-128-gcm:top%3Asecret@ss.example.net:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.net#Office%20SS';
  const result = convertSubscription(Buffer.from(link).toString('base64'));
  assert.equal(result.converted, 1);
  assert.match(result.config, /Office SS = ss, ss\.example\.net, 8388/);
  assert.match(result.config, /encrypt-method=aes-128-gcm/);
  assert.match(result.config, /password=top:secret/);
  assert.match(result.config, /obfs=http/);
  assert.match(result.config, /obfs-host=cdn\.example\.net/);
});

test('converts supported Clash YAML proxies and skips VLESS', () => {
  const source = `proxies:
  - name: Edge Vmess
    type: vmess
    server: vmess.example.net
    port: 443
    uuid: 11111111-2222-4333-8444-555555555555
    alterId: 0
    cipher: auto
    tls: true
    servername: edge.example.net
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.net
  - name: Not VLESS
    type: vless
    server: vless.example.net
    port: 443
    uuid: 11111111-2222-4333-8444-555555555555
  - name: SS Node
    type: ss
    server: ss.example.net
    port: 443
    cipher: chacha20-ietf-poly1305
    password: secret
`;
  const result = convertSubscription(source);
  assert.equal(result.converted, 2);
  assert.deepEqual(result.skippedByProtocol, { vless: 1 });
  assert.match(result.config, /Edge Vmess = vmess/);
  assert.match(result.config, /sni=edge\.example\.net/);
  assert.match(result.config, /ws-headers=Host:cdn\.example\.net/);
  assert.match(result.config, /SS Node = ss/);
});

test('maps TUIC v4 tokens and TUIC v5 UUID/password credentials separately', () => {
  const source = [
    'tuic://legacy-token@tuic4.example.net:443?alpn=h3#TUIC%20v4',
    'tuic://11111111-2222-4333-8444-555555555555:secret@tuic5.example.net:443?alpn=h3#TUIC%20v5',
  ].join('\n');
  const result = convertSubscription(source);

  assert.equal(result.converted, 2);
  assert.match(result.config, /TUIC v4 = tuic, tuic4\.example\.net, 443, token=legacy-token, alpn=h3/);
  assert.match(result.config, /TUIC v5 = tuic-v5, tuic5\.example\.net, 443, uuid=11111111-2222-4333-8444-555555555555, password=secret, alpn=h3/);
});

test('maps supported VMess cipher names and skips unsupported ciphers', () => {
  const supported = {
    add: 'vmess.example.net',
    port: 443,
    id: '11111111-2222-4333-8444-555555555555',
    net: 'tcp',
    scy: 'chacha20-poly1305',
    ps: 'VMess Chacha',
  };
  const unsupported = { ...supported, scy: 'none', ps: 'VMess None' };
  const input = [supported, unsupported]
    .map(node => `vmess://${Buffer.from(JSON.stringify(node)).toString('base64')}`)
    .join('\n');
  const result = convertSubscription(input);

  assert.equal(result.converted, 1);
  assert.deepEqual(result.skippedByProtocol, { vmess: 1 });
  assert.match(result.config, /encrypt-method=chacha20-ietf-poly1305/);
});

test('rejects empty or unrecognized input and private subscription targets', async () => {
  assert.throws(() => convertSubscription(''), /empty subscription/i);
  assert.throws(() => convertSubscription('subscription expired'), /Could not find supported/i);
  assert.throws(() => validateSourceUrl('file:///etc/passwd'), /Only http\(s\)/i);
  await assert.rejects(fetchSubscription('http://127.0.0.1/latest'), /public IP/i);
});

test('accepts a direct share link without fetching it', async () => {
  const direct = vmessLink('Direct node');
  assert.equal(validateSourceUrl(direct).direct, direct);
  const result = convertSubscription(await fetchSubscription(direct));
  assert.equal(result.converted, 1);
  assert.match(result.config, /Direct node = vmess/);
});

test('extracts nodes from an existing Surge configuration', () => {
  const source = `#!MANAGED-CONFIG https://example.com/sub interval=43200
[General]
loglevel = notify

[Proxy]
Trojan Node = trojan, edge.example.net, 443, password=secret, sni=edge.example.net
VMess Node = vmess, vm.example.net, 443, username=11111111-2222-4333-8444-555555555555, ws=true

[Proxy Group]
Proxy = select, Trojan Node, VMess Node
`;
  const result = convertSubscription(source);

  assert.equal(result.total, 2);
  assert.equal(result.converted, 2);
  assert.match(result.config, /^Trojan Node = trojan, edge\.example\.net, 443/m);
  assert.match(result.config, /^VMess Node = vmess, vm\.example\.net, 443/m);
  assert.doesNotMatch(result.config, /\[Proxy\]/);
  assert.match(result.fullConfig, /\[Proxy\]\nTrojan Node = trojan/);
});
