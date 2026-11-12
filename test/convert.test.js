import test from 'node:test';
import assert from 'node:assert/strict';
import { convertSubscription } from '../src/convert.js';
import { fetchSubscription, validateSourceUrl } from '../src/fetch-source.js';
import { buildManagedConfigUrl, prependManagedConfig } from '../src/managed-config.js';

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
    'vless://11111111-2222-4333-8444-555555555555@vless.example.net:443?security=tls#VLESS%20TLS',
    'ssr://c29tZS1ub2Rl',
  ].join('\n');

  const result = convertSubscription(input);
  assert.equal(result.total, 5);
  assert.equal(result.converted, 4);
  assert.equal(result.skipped, 1);
  assert.deepEqual(result.skippedByProtocol, { ssr: 1 });
  assert.match(result.config, /VMess WebSocket = vmess, vm\.example\.net, 443/);
  assert.match(result.config, /username=11111111-2222-4333-8444-555555555555/);
  assert.match(result.config, /ws-path=\/tunnel/);
  assert.match(result.config, /Trojan TLS = trojan, edge\.example\.net, 443, password=p@ss/);
  assert.match(result.config, /Fast UDP = hysteria2, udp\.example\.net, 8443/);
  assert.match(result.config, /salamander-password=veil/);
  assert.match(result.config, /VLESS TLS = vless, vless\.example\.net, 443, username=11111111-2222-4333-8444-555555555555, tls=true/);
  assert.doesNotMatch(result.config, /ssr/i);
  assert.match(result.fullConfig, /^\[General\]\nloglevel = notify/m);
  assert.match(result.fullConfig, /\[Proxy\]\nVMess WebSocket = vmess/);
  assert.match(result.fullConfig, /\[Proxy Group\]\nProxy = select, VMess WebSocket, Trojan TLS, Fast UDP, VLESS TLS, DIRECT/);
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

test('converts supported Clash YAML proxies including VLESS', () => {
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
  assert.equal(result.converted, 3);
  assert.deepEqual(result.skippedByProtocol, {});
  assert.match(result.config, /Edge Vmess = vmess/);
  assert.match(result.config, /sni=edge\.example\.net/);
  assert.match(result.config, /ws-headers=Host:cdn\.example\.net/);
  assert.match(result.config, /Not VLESS = vless, vless\.example\.net, 443, username=11111111-2222-4333-8444-555555555555/);
  assert.match(result.config, /SS Node = ss/);
});

test('maps VLESS REALITY, Vision, WebSocket and gRPC share-link parameters', () => {
  const source = [
    'vless://11111111-2222-4333-8444-555555555555@reality.example.net:443?security=reality&pbk=test-public-key&sid=abcdef&sni=front.example.net&flow=xtls-rprx-vision#Reality',
    'vless://11111111-2222-4333-8444-555555555555@ws.example.net:443?type=ws&security=tls&host=cdn.example.net&path=%2Fvless#VLESS%20WS',
    'vless://11111111-2222-4333-8444-555555555555@grpc.example.net:443?type=grpc&security=tls&serviceName=mygrpc&authority=grpc.example.net&mode=multi#VLESS%20gRPC',
    'vless://11111111-2222-4333-8444-555555555555@xhttp.example.net:443?type=xhttp&security=tls#Unsupported',
  ].join('\n');
  const result = convertSubscription(source);

  assert.equal(result.converted, 3);
  assert.deepEqual(result.skippedByProtocol, { vless: 1 });
  assert.match(result.config, /Reality = vless, reality\.example\.net, 443, username=11111111-2222-4333-8444-555555555555, flow=xtls-rprx-vision, reality-public-key=test-public-key, reality-short-id=abcdef, sni=front\.example\.net/);
  assert.match(result.config, /VLESS WS = vless, ws\.example\.net, 443, username=11111111-2222-4333-8444-555555555555, tls=true, ws=true, ws-path=\/vless, ws-headers=Host:cdn\.example\.net/);
  assert.match(result.config, /VLESS gRPC = vless, grpc\.example\.net, 443, username=11111111-2222-4333-8444-555555555555, tls=true, grpc=true, grpc-service-name=mygrpc, grpc-authority=grpc\.example\.net, grpc-mode=multi/);
});

test('converts AnyTLS share links and preserves the reuse setting', () => {
  const source = 'anytls://secret@anytls.example.net:443?sni=front.example.net&reuse=false&alpn=h2#AnyTLS';
  assert.equal(validateSourceUrl(source).direct, source);
  const result = convertSubscription(source);

  assert.equal(result.converted, 1);
  assert.match(result.config, /AnyTLS = anytls, anytls\.example\.net, 443, password=secret, sni=front\.example\.net, reuse=false, alpn=h2/);
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
  assert.match(result.config, /^VLESS = vless/m);
  assert.match(result.config, /^External = external/m);
  assert.doesNotMatch(result.config, /^SSR =/m);
  assert.match(result.fullConfig, /\[WireGuard office\]/);
  assert.match(result.fullConfig, /\[Tailscale home\][\s\S]*auth-key = test-auth-key/);
  assert.match(result.fullConfig, /\[Keystore\]\nssh-key = type=openssh-private-key/);
  assert.match(result.fullConfig, /cert1 = base64=dGVzdA==, password=test-pass/);
  assert.doesNotMatch(result.fullConfig, /unused-key/);
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
