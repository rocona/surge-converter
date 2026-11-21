import test from 'node:test';
import assert from 'node:assert/strict';
import { convertSubscription } from '../src/convert.js';
import { fetchSubscription, validateSourceUrl } from '../src/fetch-source.js';
import { buildManagedConfigUrl, prependManagedConfig } from '../src/managed-config.js';

function vmessLink(name = 'VMess WebSocket', network = 'ws') {
  const payload = {
    add: 'vm.example.net',
    port: '443',
    id: '11111111-2222-4333-8444-555555555555',
    aid: '0',
    net: network,
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
    'ssr://c29tZS1ub2Rl',
  ].join('\n');

  const result = convertSubscription(input);
  assert.equal(result.total, 4);
  assert.equal(result.converted, 3);
  assert.equal(result.skipped, 1);
  assert.deepEqual(result.skippedByProtocol, { ssr: 1 });
  assert.match(result.config, /VMess WebSocket = vmess, vm\.example\.net, 443/);
  assert.match(result.config, /username=11111111-2222-4333-8444-555555555555/);
  assert.match(result.config, /ws-path=\/tunnel/);
  assert.match(result.config, /Trojan TLS = trojan, edge\.example\.net, 443, password=p@ss/);
  assert.match(result.config, /Fast UDP = hysteria2, udp\.example\.net, 8443/);
  assert.match(result.config, /salamander-password=veil/);
  assert.doesNotMatch(result.config, /ssr/i);
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

test('converts Clash YAML including VLESS and filters it in legacy mode', () => {
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
  - name: VLESS Node
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
  assert.equal(result.converted, 3);
  assert.equal(result.skipped, 0);
  assert.match(result.config, /Edge Vmess = vmess/);
  assert.match(result.config, /sni=edge\.example\.net/);
  assert.match(result.config, /ws-headers=Host:cdn\.example\.net/);
  assert.match(result.config, /VLESS Node = vless/);
  assert.deepEqual(convertSubscription(source, { legacy: true }).skippedByProtocol, { vless: 1 });
  assert.match(result.config, /SS Node = ss/);
});

test('preserves flag and emoji sequences in node names', () => {
  const source = `proxies:
  - name: "🇭🇰 Hong Kong"
    type: socks5
    server: hk.example.net
    port: 1080
  - name: "👨‍👩‍👧‍👦 Family"
    type: socks5
    server: family.example.net
    port: 1080
  - name: "🇯🇵 = Tokyo"
    type: socks5
    server: tokyo.example.net
    port: 1080
`;
  const result = convertSubscription(source);

  assert.deepEqual(result.names, ['🇭🇰 Hong Kong', '👨‍👩‍👧‍👦 Family', '🇯🇵 _ Tokyo']);
  assert.match(result.config, /^🇭🇰 Hong Kong = socks5,/m);
  assert.match(result.config, /^👨‍👩‍👧‍👦 Family = socks5,/m);
  assert.match(result.config, /^🇯🇵 _ Tokyo = socks5,/m);
});

test('converts REALITY and WebSocket VLESS and skips unsupported transport', () => {
  const source = [
    `vless://11111111-2222-4333-8444-555555555555@reality.example.net:443?security=reality&pbk=${Buffer.alloc(32, 1).toString('base64url')}&sid=abcdef&sni=front.example.net&flow=xtls-rprx-vision#Reality`,
    'vless://11111111-2222-4333-8444-555555555555@ws.example.net:443?type=ws&security=tls&host=cdn.example.net&path=%2Fvless#VLESS%20WS',
    'vless://demo@example.net:443?type=kcp#Unsupported',
    vmessLink('Supported VMess'),
  ].join('\n');
  const result = convertSubscription(source);

  assert.equal(result.total, 4);
  assert.equal(result.converted, 3);
  assert.deepEqual(result.skippedByProtocol, { vless: 1 });
  assert.match(result.config, /^Supported VMess = vmess/m);
  assert.match(result.config, /^Reality = vless,.*flow=xtls-rprx-vision.*reality-short-id=abcdef/m);
  assert.match(result.config, /^VLESS WS = vless,.*tls=true.*ws-path=\/vless.*ws-headers=Host:cdn\.example\.net/m);
  assert.throws(
    () => convertSubscription(source.split('\n').slice(0, 2).join('\n'), { legacy: true }),
    error => error.status === 422 && /vless: 2/i.test(error.message),
  );
});

test('converts AnyTLS share links and preserves the reuse setting', () => {
  const source = 'anytls://secret@anytls.example.net:443?sni=front.example.net&reuse=false&alpn=h2#AnyTLS';
  assert.equal(validateSourceUrl(source).direct, source);
  const result = convertSubscription(source);

  assert.equal(result.converted, 1);
  assert.match(result.config, /AnyTLS = anytls, anytls\.example\.net, 443, password=secret, sni=front\.example\.net, reuse=false, alpn=h2/);
});

test('maps VMess and Trojan HTTPUpgrade without downgrading legacy output to WebSocket', () => {
  const links = [vmessLink('VMess Upgrade', 'httpupgrade'),
    'trojan://demo@example.net:443?type=httpupgrade&host=cdn.example.net&path=%2Fup#Trojan',
    vmessLink('Regular WS')].join('\n');
  const yaml = `proxies:
  - {name: VMess Upgrade, type: vmess, server: example.net, port: 443, uuid: 11111111-2222-4333-8444-555555555555, network: ws, ws-opts: {v2ray-http-upgrade: true, path: /up}}
  - {name: Trojan Upgrade, type: trojan, server: example.net, port: 443, password: demo, network: httpupgrade, http-upgrade-opts: {host: cdn.example.net, path: /up}}
  - {name: Regular WS, type: trojan, server: example.net, port: 443, password: demo, network: ws}
`;
  for (const source of [links, yaml, `[Proxy]\n${convertSubscription(links).config}`]) {
    const result = convertSubscription(source);
    assert.equal(result.converted, 3);
    assert.equal(result.config.match(/ws-http-upgrade=true/g)?.length, 2);
    assert.match(result.config, /ws-path=\/up, ws-headers=Host:cdn\.example\.net/);
    const legacy = convertSubscription(source, { legacy: true });
    assert.equal(legacy.converted, 1);
    assert.match(legacy.config, /^Regular WS = /m);
    assert.deepEqual(legacy.skippedByProtocol, { vmess: 1, trojan: 1 });
  }
});

test('maps Hysteria2 authority port lists and keeps YAML certificate pins', () => {
  const pin = 'a1'.repeat(32);
  const links = convertSubscription([
    `hy2://demo@[2001:db8::1]:443,5000-6000/?pinSHA256=${pin}#Port%20List`,
    'hysteria2://demo@example.net:6000-5000#Bad',
  ].join('\n'));
  assert.match(links.config, /port-hopping="443;5000-6000"/);
  assert.match(links.config, new RegExp(`server-cert-fingerprint-sha256=${pin}`));
  assert.deepEqual(links.skippedByProtocol, { hysteria2: 1 });
  const yaml = convertSubscription(`proxies:
  - {name: Pinned, type: hysteria2, server: example.net, port: 443, password: demo, fingerprint: '${pin}'}
  - {name: Invalid, type: hysteria2, server: example.net, port: 443, password: demo, pinSHA256: invalid}
`);
  assert.match(yaml.config, new RegExp(`server-cert-fingerprint-sha256=${pin}`));
  assert.deepEqual(yaml.skippedByProtocol, { hysteria2: 1 });
});

test('maps VLESS gRPC and basic XHTTP, dropping combinations Surge cannot use', () => {
  const shadow = Buffer.from('none:demo@example.net:443').toString('base64url');
  const result = convertSubscription([
    `vless://${shadow}?tls=1&obfs=grpc&path=service&remarks=Legacy%20Format`,
    'vless://demo@example.net:443?type=xhttp&security=tls&path=%2Fx&host=cdn.example.net&mode=packet-up#XHTTP',
    'vless://demo@example.net:443?type=xhttp&extra=%7B%22downloadSettings%22%3A%7B%7D%7D#Split',
    'vless://demo@example.net:443?type=grpc#NoTLS',
    'vless://demo@example.net:443?type=ws&security=tls&flow=xtls-rprx-vision#InvalidVision',
  ].join('\n'));
  assert.equal(result.converted, 2);
  assert.deepEqual(result.skippedByProtocol, { vless: 3 });
  assert.match(result.config, /^Legacy Format = vless,.*tls=true.*grpc=true, grpc-service-name=service/m);
  assert.match(result.config, /^XHTTP = vless,.*xhttp-path=\/x, xhttp-host=cdn\.example\.net, xhttp-mode=packet-up/m);
});

test('converts current Clash proxy types and Hysteria 2 port hopping options', () => {
  const source = `proxies:
  - name: AnyTLS
    type: anytls
    server: anytls.example.net
    port: 443
    password: secret
    sni: front.example.net
    reuse: false
  - name: Snell v6
    type: snell
    server: snell.example.net
    port: 443
    psk: secret
    version: 6
    mode: unshaped
  - name: MASQUE
    type: masque
    server: masque.example.net
    port: 443
    username: proxy-user
    password: secret
    port-hopping: 443,5000-5002
    port-hopping-interval: 20
  - name: Trust Tunnel
    type: trust-tunnel
    server: tunnel.example.net
    port: 443
    username: user
    password: secret
    h3: true
    max-streams: 4
    headers:
      X-Padding: dynamic
    client-random-auth-key: test-client-key
  - name: SSH
    type: ssh
    server: ssh.example.net
    port: 22
    username: root
    password: secret
    idle-timeout: 240
  - name: Hysteria 2
    type: hysteria2
    server: hy2.example.net
    port: 443
    password: secret
    obfs: gecko
    obfs-password: secret
    ports: 443,8443-8445
    hop-interval: 30
    down: 100 Mbps
  - name: TUIC v5
    type: tuic
    server: tuic.example.net
    port: 443
    uuid: 11111111-2222-4333-8444-555555555555
    password: secret
    ports: 443,8443-8445
    hop-interval: 25
  - name: H2 CONNECT
    type: h2-connect
    server: h2.example.net
    port: 443
    headers:
      X-Client: Surge
    max-streams: 8
    udp-relay: true
  - name: SOCKS5 TLS
    type: socks5
    server: socks.example.net
    port: 443
    username: user
    password: secret
    tls: true
    udp-relay: true
`;
  const result = convertSubscription(source);

  assert.equal(result.converted, 9);
  assert.deepEqual(result.skippedByProtocol, {});
  assert.match(result.config, /AnyTLS = anytls, anytls\.example\.net, 443, password=secret, sni=front\.example\.net, reuse=false/);
  assert.match(result.config, /Snell v6 = snell, snell\.example\.net, 443, psk=secret, version=6, mode=unshaped/);
  assert.match(result.config, /MASQUE = masque, masque\.example\.net, 443, username=proxy-user, password=secret, port-hopping="443;5000-5002", port-hopping-interval=20/);
  assert.match(result.config, /Trust Tunnel = trust-tunnel, tunnel\.example\.net, 443, username=user, password=secret, h3=true, max-streams=4/);
  assert.match(result.config, /X-Padding:dynamic/);
  assert.match(result.config, /client-random-auth-key=test-client-key/);
  assert.match(result.config, /SSH = ssh, ssh\.example\.net, 22, username=root, password=secret, idle-timeout=240/);
  assert.match(result.config, /Hysteria 2 = hysteria2, hy2\.example\.net, 443, password=secret, gecko-password=secret, port-hopping="443;8443-8445", port-hopping-interval=30, download-bandwidth=100/);
  assert.match(result.config, /TUIC v5 = tuic-v5, tuic\.example\.net, 443, uuid=11111111-2222-4333-8444-555555555555, password=secret, port-hopping="443;8443-8445", port-hopping-interval=25/);
  assert.match(result.config, /H2 CONNECT = h2-connect, h2\.example\.net, 443, headers=X-Client:Surge, max-streams=8, udp-relay=true/);
  assert.match(result.config, /SOCKS5 TLS = socks5-tls, socks\.example\.net, 443, username=user, password=secret, udp-relay=true/);
});

test('converts Clash WireGuard nodes into a complete Surge configuration', () => {
  const source = `proxies:
  - name: WARP
    type: wireguard
    ip: 172.16.0.2/32
    ipv6: 2606:4700:110::2/128
    private-key: test-private-key
    dns:
      - 1.1.1.1
      - 2606:4700:4700::1111
    mtu: 1280
    peers:
      - server: engage.cloudflareclient.com
        port: 2408
        public-key: test-public-key
        allowed-ips:
          - 0.0.0.0/0
          - ::/0
        reserved: [83, 12, 235]
`;
  const result = convertSubscription(source);

  assert.equal(result.converted, 1);
  assert.equal(result.requiresFullConfig, true);
  assert.match(result.config, /WARP = wireguard, section-name=wireguard-1/);
  assert.match(result.fullConfig, /\[WireGuard wireguard-1\]/);
  assert.match(result.fullConfig, /self-ip = 172\.16\.0\.2/);
  assert.match(result.fullConfig, /self-ip-v6 = 2606:4700:110::2/);
  assert.match(result.fullConfig, /allowed-ips = "0\.0\.0\.0\/0, ::\/0"/);
  assert.match(result.fullConfig, /client-id = 83\/12\/235/);
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

test('keeps supported native Surge protocols and required companion sections', () => {
  const source = `[General]
loglevel = notify

[Proxy]
VLESS = vless, vless.example.net, 443, username=11111111-2222-4333-8444-555555555555, flow=xtls-rprx-vision, reality-public-key=test-public-key
AnyTLS = anytls, anytls.example.net, 443, password=secret
MASQUE = masque, masque.example.net, 443, username=user, password=secret
Snell v6 = snell, snell.example.net, 443, psk=secret, version=6
Trust Tunnel = trust-tunnel, tunnel.example.net, 443, username=user, password=secret, h3=true
HTTP TLS = https, cert.example.net, 443, client-cert=cert1
SSH = ssh, ssh.example.net, 22, username=root, private-key=ssh-key
WG = wireguard, section-name=office
Tailnet = tailscale, section-name=home
External = external, exec=/usr/bin/ssh, local-port=1080
SSR = ssr, ssr.example.net, 443

[Proxy Group]
Proxy = select, VLESS, AnyTLS, MASQUE, Snell v6, Trust Tunnel, HTTP TLS, SSH, WG, Tailnet, External

[WireGuard office]
private-key = test-private-key
self-ip = 10.0.0.2
peer = (public-key = test-public-key, allowed-ips = 0.0.0.0/0, endpoint = wg.example.net:51820)

[Tailscale home]
auth-key = test-auth-key
hostname = surge

[Keystore]
ssh-key = type=openssh-private-key, base64=dGVzdA==
cert1 = base64=dGVzdA==, password=test-pass
unused-key = type=openssh-private-key, base64=dGVzdA==
`;
  const result = convertSubscription(source);

  assert.equal(result.total, 11);
  assert.equal(result.converted, 10);
  assert.equal(result.skipped, 1);
  assert.deepEqual(result.skippedByProtocol, { ssr: 1 });
  assert.equal(result.requiresFullConfig, true);
  assert.match(result.config, /^VLESS = vless,/m);
  assert.doesNotMatch(convertSubscription(source, { legacy: true }).config, /^VLESS =/m);
  assert.match(result.config, /^External = external/m);
  assert.doesNotMatch(result.config, /^SSR =/m);
  assert.match(result.fullConfig, /\[WireGuard office\]/);
  assert.match(result.fullConfig, /\[Tailscale home\][\s\S]*auth-key = test-auth-key/);
  assert.match(result.fullConfig, /\[Keystore\]\nssh-key = type=openssh-private-key/);
  assert.match(result.fullConfig, /cert1 = base64=dGVzdA==, password=test-pass/);
  assert.doesNotMatch(result.fullConfig, /unused-key/);
});

test('filters subscription info and client notes without changing usable Surge nodes', () => {
  const source = `[Proxy]
剩余流量：123 GB = ss, stats.example.net, 443, encrypt-method=chacha20-ietf-poly1305, password=stats
套餐到期：长期有效 = ss, stats.example.net, 443, encrypt-method=chacha20-ietf-poly1305, password=stats
✅续费网址:https://example.net/renew = ss, stats.example.net, 443, encrypt-method=chacha20-ietf-poly1305, password=stats
安卓-clashmeta客户端 = vmess, client.example.net, 443, username=00000000-0000-4000-8000-000000000000
推荐ClashMI，Karing，小火箭客户端 = ss, note.example.net, 443, encrypt-method=chacha20-ietf-poly1305, password=note
🇭🇰香港Ai/流媒体节点 = hysteria2, hk.example.net, 443, password=fixture-secret, sni=hk.example.net, skip-cert-verify=true, port-hopping=443,8443-8450, port-hopping-interval=30

[Proxy Group]
Proxy = select, 🇭🇰香港Ai/流媒体节点
`;

  const result = convertSubscription(source);

  assert.equal(result.total, 6);
  assert.equal(result.converted, 1);
  assert.equal(result.skipped, 5);
  assert.equal(result.filteredByName, 5);
  assert.deepEqual(result.names, ['🇭🇰香港Ai/流媒体节点']);
  assert.equal(
    result.config,
    '🇭🇰香港Ai/流媒体节点 = hysteria2, hk.example.net, 443, password=fixture-secret, sni=hk.example.net, skip-cert-verify=true, port-hopping=443,8443-8450, port-hopping-interval=30\n',
  );
});

test('filters notices from Clash and share links while retaining real client-compatible nodes', () => {
  const source = `proxies:
  - {name: '剩余流量：100 GB', type: ss, server: stats.example.net, port: 443, cipher: aes-128-gcm, password: stats}
  - {name: '若无HY节点-更换客户端即可', type: ss, server: stats.example.net, port: 443, cipher: aes-128-gcm, password: stats}
  - {name: '🇺🇸美国HY2轻量-小火箭也能用HY', type: hysteria2, server: hy.example.net, port: 443, password: test-secret}
`;
  const clash = convertSubscription(source);
  assert.equal(clash.filteredByName, 2);
  assert.deepEqual(clash.names, ['🇺🇸美国HY2轻量-小火箭也能用HY']);

  const links = convertSubscription([
    'trojan://secret@note.example.net:443#%E5%A5%97%E9%A4%90%E5%88%B0%E6%9C%9F',
    'trojan://secret@real.example.net:443#%F0%9F%87%B9%F0%9F%87%BC%E5%8F%B0%E6%B9%BE%E5%AE%B6%E5%AE%BD1-GPT',
  ].join('\n'));
  assert.equal(links.filteredByName, 1);
  assert.deepEqual(links.names, ['🇹🇼台湾家宽1-GPT']);
});

test('preserves Hysteria2 certificate pins and slashes in share-link names', () => {
  const fingerprint = 'ab'.repeat(32);
  const source = `hysteria2://fixture-secret@hy.example.net:443?sni=hy.example.net&insecure=false&pinSHA256=${fingerprint}&mport=50000-53000#AI%2F%E6%B5%81%E5%AA%92%E4%BD%93`;
  const result = convertSubscription(source);
  assert.deepEqual(result.names, ['AI/流媒体']);
  assert.match(result.config, new RegExp(`server-cert-fingerprint-sha256=${fingerprint}`));
  assert.match(result.config, /port-hopping=50000-53000/);
  assert.doesNotMatch(result.config, /skip-cert-verify=true/);
  assert.throws(() => convertSubscription(source.replace(fingerprint, 'invalid')), /No Surge-compatible nodes/);
});

test('prepends a Surge managed-config directive to full output', () => {
  const endpoint = buildManagedConfigUrl({
    protocol: 'https',
    host: 'surge-converter.zeabur.app',
    pathname: '/',
    search: '?url=https%3A%2F%2Fexample.com%2Fsubscription',
  });
  const output = prependManagedConfig('[General]\nloglevel = notify\n', endpoint);

  assert.equal(
    output,
    '#!MANAGED-CONFIG https://surge-converter.zeabur.app?url=https%3A%2F%2Fexample.com%2Fsubscription interval=43200 strict=true\n[General]\nloglevel = notify\n',
  );
});
