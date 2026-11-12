import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { parse as parseYaml } from 'yaml';

const URI_PATTERN = /(?:ssr?|vmess|vless|anytls|trojan|hysteria2|hy2|tuic):\/\/[^\s<>"']+/gi;
const SAFE_VALUE = /^[A-Za-z0-9._~:/+@!$%&*()\[\]-]+$/;
const SUPPORTED_SS_METHODS = new Set([
  '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
  'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
  'rc4', 'rc4-md5',
]);
const SURGE_PROXY_TYPES = new Set([
  'http', 'https', 'h2-connect', 'socks5', 'socks5-tls', 'ss', 'vmess', 'trojan', 'hysteria2', 'tuic', 'tuic-v5',
  'snell', 'masque', 'anytls', 'trust-tunnel', 'ssh', 'wireguard', 'tailscale', 'external',
]);

export function convertSubscription(body) {
  const raw = String(body ?? '').replace(/^\uFEFF/, '').trim();
  if (!raw) throw new ConversionError('The source returned an empty subscription.', 422);

  const candidates = [raw];
  const decoded = decodeBase64Subscription(raw);
  if (decoded && decoded !== raw) candidates.push(decoded);

  for (const text of candidates) {
    const surgeConfig = parseSurgeProxySection(text);
    if (surgeConfig) return convertSurgeProxies(surgeConfig);

    const proxies = parseClashProxies(text);
    if (proxies) return convertClashProxies(proxies);

    const uris = text.match(URI_PATTERN) ?? [];
    if (uris.length) return convertShareLinks(uris);
  }

  throw new ConversionError('Could not find supported share links or a Clash proxies list in the source.', 422);
}

function parseSurgeProxySection(text) {
  const sections = new Map();
  let currentName = '';
  let currentLines = [];
  const save = () => {
    if (currentName) sections.set(currentName.toLowerCase(), { name: currentName, lines: currentLines });
  };

  for (const line of text.split(/\r?\n/)) {
    const header = line.match(/^\s*\[([^\]\r\n]+)\]\s*$/);
    if (header) {
      save();
      currentName = header[1].trim();
      currentLines = [];
    } else if (currentName) {
      currentLines.push(line);
    }
  }
  save();

  const proxySection = sections.get('proxy');
  if (!proxySection) return null;
  return {
    lines: proxySection.lines.map(line => line.trim()).filter(line => line && !line.startsWith('#')),
    sections,
  };
}

function convertSurgeProxies({ lines, sections }) {
  const entries = [];
  const skippedByProtocol = {};
  const companionSectionNames = new Map([['wireguard', new Set()], ['tailscale', new Set()]]);
  const keystoreReferences = new Set();
  const keystore = sections.get('keystore');
  const keystoreNames = new Set((keystore?.lines ?? []).map(line => line.match(/^\s*([^=]+?)\s*=/)?.[1]?.trim()).filter(Boolean));

  for (const line of lines) {
    const match = line.match(/^([^=\r\n]+?)\s*=\s*([a-z0-9-]+)\s*,\s*(.+)$/i);
    const protocol = String(match?.[2] ?? 'invalid').toLowerCase();
    try {
      if (!match || !SURGE_PROXY_TYPES.has(protocol)) {
        bump(skippedByProtocol, protocol);
        continue;
      }

      if (companionSectionNames.has(protocol)) {
        const sectionName = readSurgeParameter(match[3], 'section-name');
        if (!sectionName || !sections.has(`${protocol} ${sectionName}`.toLowerCase())) {
          bump(skippedByProtocol, protocol);
          continue;
        }
        companionSectionNames.get(protocol).add(sectionName.toLowerCase());
      }

      const keystoreName = readSurgeParameter(match[3], 'client-cert')
        || (protocol === 'ssh' ? readSurgeParameter(match[3], 'private-key') : '');
      if (keystoreName) {
        if (!keystoreNames.has(keystoreName)) {
          bump(skippedByProtocol, protocol);
          continue;
        }
        keystoreReferences.add(keystoreName);
      }

      const name = safeName(match[1]);
      if (!name) throw new Error('Invalid proxy name');
      entries.push({ name, line: `${name} = ${protocol}, ${match[3].trim()}` });
    } catch {
      bump(skippedByProtocol, protocol);
    }
  }

  const extraSections = [];
  for (const [protocol, names] of companionSectionNames) {
    for (const sectionName of names) {
      const section = sections.get(`${protocol} ${sectionName}`);
      extraSections.push(formatSurgeSection(section));
    }
  }
  if (keystoreReferences.size && keystore) {
    const keys = keystore.lines.filter(line => keystoreReferences.has(line.match(/^\s*([^=]+?)\s*=/)?.[1]?.trim()));
    if (keys.length) extraSections.push(`[${keystore.name}]\n${keys.join('\n')}`);
  }

  return finishSurgeConversion(entries, skippedByProtocol, lines.length, extraSections);
}

function readSurgeParameter(text, name) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = text.match(new RegExp(`(?:^|,)\\s*${escapedName}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^,\\s]+))`, 'i'));
  return match?.[1] ?? match?.[2] ?? match?.[3] ?? '';
}

function formatSurgeSection(section) {
  return `[${section.name}]\n${section.lines.join('\n').trim()}`;
}

function finishSurgeConversion(entries, skippedByProtocol, total, extraSections = []) {
  if (!entries.length) {
    const skipped = Object.entries(skippedByProtocol)
      .map(([protocol, count]) => `${protocol}: ${count}`)
      .join(', ');
    throw new ConversionError(
      skipped ? `No Surge-compatible nodes found. Skipped: ${skipped}.` : 'No Surge-compatible nodes found.',
      422,
    );
  }

  const config = entries.map(({ line }) => line).join('\n') + '\n';
  return {
    config,
    fullConfig: `${formatSurgeConfigFromLines(entries)}${extraSections.length ? `\n${extraSections.join('\n\n')}\n` : ''}`,
    requiresFullConfig: extraSections.length > 0,
    names: entries.map(({ name }) => name),
    total,
    converted: entries.length,
    skipped: total - entries.length,
    skippedByProtocol,
  };
}

function formatSurgeConfigFromLines(entries) {
  const nodes = entries.map(({ line }) => line).join('\n');
  const names = entries.map(({ name }) => name).join(', ');
  return [
    '[General]',
    'loglevel = notify',
    '',
    '[Proxy]',
    nodes,
    '',
    '[Proxy Group]',
    `Proxy = select, ${names}, DIRECT`,
    '',
    '[Rule]',
    'FINAL, Proxy',
    '',
  ].join('\n');
}

export class ConversionError extends Error {
  constructor(message, status = 422) {
    super(message);
    this.name = 'ConversionError';
    this.status = status;
  }
}

function decodeBase64Subscription(text) {
  const compact = text.replace(/\s+/g, '');
  if (!compact || !/^[A-Za-z0-9_+/=-]+$/.test(compact) || compact.length % 4 === 1) return null;

  try {
    const bytes = Buffer.from(compact.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
    if (!decoded || /\u0000/.test(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}

function parseClashProxies(text) {
  if (!/^\s*(?:proxies|proxy-groups|mixed-port|port|allow-lan|mode)\s*:/m.test(text)) return null;
  try {
    const config = parseYaml(text, { maxAliasCount: 20 });
    return Array.isArray(config?.proxies) ? config.proxies : null;
  } catch {
    return null;
  }
}

function convertShareLinks(uris) {
  const entries = [];
  const skippedByProtocol = {};

  for (const uri of uris) {
    const protocol = uri.slice(0, uri.indexOf(':')).toLowerCase();
    try {
      const entry = parseShareLink(uri);
      if (!entry) {
        bump(skippedByProtocol, protocol);
        continue;
      }
      entries.push(entry);
    } catch {
      bump(skippedByProtocol, protocol);
    }
  }

  return finishConversion(entries, skippedByProtocol, uris.length);
}

function convertClashProxies(proxies) {
  const entries = [];
  const skippedByProtocol = {};

  for (const [index, proxy] of proxies.entries()) {
    const protocol = String(proxy?.type ?? 'unknown').toLowerCase();
    try {
      const entry = parseClashProxy(proxy, index);
      if (!entry) {
        bump(skippedByProtocol, protocol);
        continue;
      }
      entries.push(entry);
    } catch {
      bump(skippedByProtocol, protocol);
    }
  }

  return finishConversion(entries, skippedByProtocol, proxies.length);
}

function finishConversion(entries, skippedByProtocol, total) {
  const named = assignUniqueNames(entries);
  if (!named.length) {
    const skipped = Object.entries(skippedByProtocol)
      .map(([protocol, count]) => `${protocol}: ${count}`)
      .join(', ');
    throw new ConversionError(
      skipped ? `No Surge-compatible nodes found. Skipped: ${skipped}.` : 'No Surge-compatible nodes found.',
      422,
    );
  }

  const extraSections = [...new Set(named.map(({ extraSection }) => extraSection).filter(Boolean))];
  return {
    config: named.map(formatProxy).join('\n') + '\n',
    fullConfig: `${formatSurgeConfig(named)}${extraSections.length ? `\n${extraSections.join('\n\n')}\n` : ''}`,
    requiresFullConfig: extraSections.length > 0,
    names: named.map(({ name }) => name),
    total,
    converted: named.length,
    skipped: total - named.length,
    skippedByProtocol,
  };
}

export function formatSurgeConfig(entries) {
  const nodes = entries.map(formatProxy).join('\n');
  const names = entries.map(({ name }) => name).join(', ');
  return [
    '[General]',
    'loglevel = notify',
    '',
    '[Proxy]',
    nodes,
    '',
    '[Proxy Group]',
    `Proxy = select, ${names}, DIRECT`,
    '',
    '[Rule]',
    'FINAL, Proxy',
    '',
  ].join('\n');
}

function parseShareLink(uri) {
  const protocol = uri.slice(0, uri.indexOf(':')).toLowerCase();
  if (protocol === 'vmess') return parseVmess(uri);
  if (protocol === 'ss') return parseShadowsocks(uri);
  if (protocol === 'anytls') return parseAnyTls(uri);
  if (protocol === 'ssr') return null;
  if (protocol === 'trojan') return parseTrojan(uri);
  if (protocol === 'hysteria2' || protocol === 'hy2') return parseHysteria2(uri);
  if (protocol === 'tuic') return parseTuic(uri);
  return null;
}

function parseVmess(uri) {
  const encoded = uri.slice(uri.indexOf('://') + 3);
  const settings = JSON.parse(decodeBase64(encoded));
  const host = normalizeHost(settings.add ?? settings.server);
  const port = normalizePort(settings.port);
  const network = String(settings.net || 'tcp').toLowerCase();
  if (!['tcp', 'ws'].includes(network)) throw new Error('Unsupported VMess transport');

  const params = [
    ['username', String(settings.id ?? settings.uuid ?? '')],
    ['vmess-aead', Number(settings.aid ?? 0) === 0 ? 'true' : 'false'],
  ];
  addVmessEncryption(params, settings.scy ?? settings.security);
  const tls = truthy(settings.tls);
  if (tls) params.push(['tls', 'true']);
  const sni = settings.sni || (tls && network === 'tcp' ? settings.host : '');
  if (sni) params.push(['sni', normalizeHost(sni)]);
  if (network === 'ws') {
    params.push(['ws', 'true']);
    const path = settings.path ? safeText(settings.path) : '';
    if (path) params.push(['ws-path', path]);
    const wsHost = settings.host ? normalizeHost(settings.host) : '';
    if (wsHost) params.push(['ws-headers', `Host:${wsHost}`]);
  }
  if (truthy(settings.allowInsecure)) params.push(['skip-cert-verify', 'true']);
  const alpn = firstAlpn(settings.alpn);
  if (alpn) params.push(['alpn', alpn]);

  return makeProxy(settings.ps || settings.name, 'vmess', host, port, params);
}

function parseAnyTls(uri) {
  const url = new URL(uri);
  const query = url.searchParams;
  const password = query.get('password') || decodePart(url.password || url.username);
  if (!password) throw new Error('Missing AnyTLS password');

  const params = [['password', safeText(password)]];
  const sni = query.get('sni') || query.get('peer') || query.get('servername');
  if (sni) params.push(['sni', normalizeHost(sni)]);
  if (isTruthyParam(query.get('allowInsecure') ?? query.get('insecure'))) params.push(['skip-cert-verify', 'true']);
  if (query.has('reuse')) params.push(['reuse', String(parseBooleanParam(query.get('reuse')))]);
  const alpn = firstAlpn(query.get('alpn'));
  if (alpn) params.push(['alpn', alpn]);

  return makeProxy(decodePart(url.hash.slice(1)), 'anytls', normalizeHost(url.hostname), normalizePort(url.port || '443'), params);
}

function parseShadowsocks(uri) {
  const hashIndex = uri.indexOf('#');
  const queryIndex = uri.indexOf('?');
  const end = [hashIndex, queryIndex].filter(index => index >= 0).reduce((min, value) => Math.min(min, value), uri.length);
  const body = uri.slice(uri.indexOf('://') + 3, end).replace(/\/$/, '');
  const fragment = hashIndex >= 0 ? decodePart(uri.slice(hashIndex + 1, queryIndex > hashIndex ? queryIndex : undefined)) : '';
  const query = new URLSearchParams(queryIndex >= 0 ? uri.slice(queryIndex + 1, hashIndex >= 0 ? hashIndex : undefined) : '');

  let method;
  let password;
  let host;
  let port;
  const at = body.lastIndexOf('@');

  if (at >= 0) {
    const userInfo = decodePart(body.slice(0, at));
    const authority = body.slice(at + 1);
    const decodedCredentials = maybeBase64(userInfo) ?? userInfo;
    const separator = decodedCredentials.indexOf(':');
    if (separator < 1) throw new Error('Invalid Shadowsocks credentials');
    method = decodedCredentials.slice(0, separator);
    password = decodedCredentials.slice(separator + 1);
    ({ host, port } = parseHostPort(authority));
  } else {
    // Legacy SIP002 form encodes method:password@host:port as one Base64 token.
    const decoded = decodeBase64(body);
    const legacyAt = decoded.lastIndexOf('@');
    const credentials = legacyAt >= 0 ? decoded.slice(0, legacyAt) : '';
    const separator = credentials.indexOf(':');
    if (legacyAt < 0 || separator < 1) throw new Error('Invalid legacy Shadowsocks link');
    method = credentials.slice(0, separator);
    password = credentials.slice(separator + 1);
    ({ host, port } = parseHostPort(decoded.slice(legacyAt + 1)));
  }

  const params = [
    ['encrypt-method', supportedShadowsocksMethod(method)],
    ['password', safeText(password)],
    ['udp-relay', 'true'],
  ];
  const plugin = query.get('plugin');
  if (plugin) {
    const pluginOptions = new URLSearchParams(plugin.replace(/;/g, '&'));
    const pluginName = plugin.split(';', 1)[0];
    const obfs = pluginOptions.get('obfs');
    const obfsHost = pluginOptions.get('obfs-host');
    if (!['obfs-local', 'simple-obfs'].includes(pluginName) || !['http', 'tls'].includes(obfs)) {
      throw new Error('Unsupported Shadowsocks plugin');
    }
    params.push(['obfs', obfs]);
    if (obfsHost) params.push(['obfs-host', normalizeHost(obfsHost)]);
  }

  return makeProxy(fragment, 'ss', host, port, params);
}

function parseTrojan(uri) {
  const url = new URL(uri);
  const query = url.searchParams;
  const transport = String(query.get('type') || query.get('network') || 'tcp').toLowerCase();
  if (!['tcp', 'ws'].includes(transport)) throw new Error('Unsupported Trojan transport');
  if (query.get('security') === 'none' || query.get('tls') === 'false') throw new Error('Trojan requires TLS');

  const params = [['password', safeText(decodePart(url.password || url.username))]];
  const sni = query.get('sni') || query.get('peer') || query.get('servername');
  if (sni) params.push(['sni', normalizeHost(sni)]);
  if (isTruthyParam(query.get('allowInsecure') ?? query.get('insecure'))) params.push(['skip-cert-verify', 'true']);
  if (transport === 'ws') addWebSocketParams(params, query.get('path') || url.pathname, query.get('host'));
  const alpn = firstAlpn(query.get('alpn'));
  if (alpn) params.push(['alpn', alpn]);

  return makeProxy(decodePart(url.hash.slice(1)), 'trojan', normalizeHost(url.hostname), normalizePort(url.port), params);
}

function parseHysteria2(uri) {
  const url = new URL(uri);
  const query = url.searchParams;
  const password = decodePart(url.password || url.username);
  if (!password) throw new Error('Missing Hysteria2 password');
  const params = [['password', safeText(password)]];
  const sni = query.get('sni') || query.get('peer') || query.get('servername');
  if (sni) params.push(['sni', normalizeHost(sni)]);
  if (isTruthyParam(query.get('insecure') ?? query.get('allowInsecure'))) params.push(['skip-cert-verify', 'true']);
  const alpn = firstAlpn(query.get('alpn'));
  if (alpn) params.push(['alpn', alpn]);

  const obfs = query.get('obfs');
  if (obfs) {
    if (!['salamander', 'gecko'].includes(obfs.toLowerCase())) throw new Error('Unsupported Hysteria2 obfuscation');
    const obfsPassword = query.get('obfs-password') || query.get('obfsPassword');
    if (!obfsPassword) throw new Error('Missing Hysteria2 obfuscation password');
    params.push([obfs.toLowerCase() === 'salamander' ? 'salamander-password' : 'gecko-password', safeText(obfsPassword)]);
  }
  const portHopping = normalizePortHopping(query.get('port-hopping') || query.get('ports') || query.get('mport'));
  if (portHopping) params.push(['port-hopping', portHopping]);
  const hoppingInterval = query.get('port-hopping-interval') || query.get('hop_interval') || query.get('hop-interval');
  if (hoppingInterval) params.push(['port-hopping-interval', String(normalizePositiveInteger(hoppingInterval, 86400))]);
  const downloadBandwidth = query.get('download-bandwidth') || query.get('downmbps') || query.get('down');
  if (downloadBandwidth) params.push(['download-bandwidth', normalizeBandwidth(downloadBandwidth)]);

  return makeProxy(decodePart(url.hash.slice(1)), 'hysteria2', normalizeHost(url.hostname), normalizePort(url.port || '443'), params);
}

function parseTuic(uri) {
  const url = new URL(uri);
  const query = url.searchParams;
  const username = decodePart(url.username);
  const password = decodePart(url.password);
  const params = [];
  let proxyType;
  if (username && password) {
    params.push(['uuid', safeText(username)], ['password', safeText(password)]);
    proxyType = 'tuic-v5';
  } else {
    const token = query.get('token') || username || password;
    if (!token) throw new Error('Missing TUIC credentials');
    params.push(['token', safeText(token)]);
    proxyType = 'tuic';
  }
  const sni = query.get('sni') || query.get('peer');
  if (sni) params.push(['sni', normalizeHost(sni)]);
  if (isTruthyParam(query.get('allowInsecure') ?? query.get('insecure'))) params.push(['skip-cert-verify', 'true']);
  const alpn = firstAlpn(query.get('alpn'));
  if (alpn) params.push(['alpn', alpn]);
  const portHopping = normalizePortHopping(query.get('port-hopping') || query.get('ports') || query.get('mport'));
  if (portHopping) params.push(['port-hopping', portHopping]);
  const hoppingInterval = query.get('port-hopping-interval') || query.get('hop_interval') || query.get('hop-interval');
  if (hoppingInterval) params.push(['port-hopping-interval', String(normalizePositiveInteger(hoppingInterval, 86400))]);
  return makeProxy(decodePart(url.hash.slice(1)), proxyType, normalizeHost(url.hostname), normalizePort(url.port), params);
}

function parseClashWireGuard(proxy, index) {
  const privateKey = safeText(proxy['private-key'] || proxy.privateKey);
  const ipv4 = proxy.ip ? normalizeWireGuardAddress(proxy.ip, 4) : '';
  const ipv6 = proxy.ipv6 ? normalizeWireGuardAddress(proxy.ipv6, 6) : '';
  if (!ipv4 && !ipv6) throw new Error('WireGuard requires a local IP address');

  const peers = Array.isArray(proxy.peers) && proxy.peers.length
    ? proxy.peers
    : [proxy];
  const sectionName = `wireguard-${index + 1}`;
  const sectionLines = [`private-key = ${formatValue(privateKey)}`];
  if (ipv4) sectionLines.push(`self-ip = ${formatValue(ipv4)}`);
  if (ipv6) sectionLines.push(`self-ip-v6 = ${formatValue(ipv6)}`);
  const dns = proxy.dns ?? proxy['dns-server'];
  if (dns) {
    const dnsServers = (Array.isArray(dns) ? dns : String(dns).split(',')).map(value => normalizeHost(value));
    sectionLines.push(`dns-server = ${formatValue(dnsServers.join(', '))}`);
  }
  if (proxy.mtu) sectionLines.push(`mtu = ${normalizePositiveInteger(proxy.mtu, 65535)}`);

  for (const peer of peers) {
    if (!peer || typeof peer !== 'object' || Array.isArray(peer)) throw new Error('Invalid WireGuard peer');
    let host;
    let port;
    if (peer.endpoint && !peer.server && !proxy.server) {
      ({ host, port } = parseHostPort(peer.endpoint));
    } else {
      host = normalizeHost(peer.server || proxy.server);
      port = normalizePort(peer.port || proxy.port);
    }
    const publicKey = safeText(peer['public-key'] || peer.publicKey || proxy['public-key'] || proxy.publicKey);
    const allowedValue = peer['allowed-ips'] || peer.allowedIps || proxy['allowed-ips'] || proxy.allowedIps;
    const allowedIps = allowedValue
      ? (Array.isArray(allowedValue) ? allowedValue : String(allowedValue).split(','))
      : [isIP(ipv4) === 4 || ipv4 ? '0.0.0.0/0' : '', isIP(ipv6) === 6 || ipv6 ? '::/0' : ''].filter(Boolean);
    if (!allowedIps.length) throw new Error('WireGuard peer requires allowed-ips');

    const fields = [
      `public-key = ${formatValue(publicKey)}`,
      `allowed-ips = ${formatValue(allowedIps.map(value => normalizeCidr(value)).join(', '))}`,
      `endpoint = ${formatValue(`${isIP(host) === 6 ? `[${host}]` : host}:${port}`)}`,
    ];
    const presharedKey = peer['preshared-key'] || peer['pre-shared-key'] || peer.presharedKey || proxy['preshared-key'] || proxy['pre-shared-key'];
    if (presharedKey) fields.push(`preshared-key = ${formatValue(presharedKey)}`);
    const keepalive = peer.keepalive ?? peer['persistent-keepalive'];
    if (keepalive !== undefined && Number(keepalive) > 0) fields.push(`keepalive = ${normalizePositiveInteger(keepalive, 65535)}`);
    const reserved = peer.reserved ?? proxy.reserved;
    if (reserved !== undefined) fields.push(`client-id = ${formatWireGuardReserved(reserved)}`);
    sectionLines.push(`peer = (${fields.join(', ')})`);
  }

  return {
    name: safeName(proxy.name),
    type: 'wireguard',
    sectionName,
    params: [['section-name', sectionName]],
    extraSection: `[WireGuard ${sectionName}]\n${sectionLines.join('\n')}`,
  };
}

function normalizeWireGuardAddress(value, family) {
  const address = safeText(value).split('/')[0];
  if (isIP(address) !== family) throw new Error('Invalid WireGuard local address');
  return address;
}

function normalizeCidr(value) {
  const text = safeText(value);
  const [address, prefix, ...extra] = text.split('/');
  const family = isIP(address);
  if (!family || extra.length) throw new Error('Invalid WireGuard allowed IP');
  if (prefix === undefined) return `${address}/${family === 4 ? 32 : 128}`;
  const bits = Number(prefix);
  if (!Number.isInteger(bits) || bits < 0 || bits > (family === 4 ? 32 : 128)) throw new Error('Invalid WireGuard allowed IP');
  return `${address}/${bits}`;
}

function normalizePositiveInteger(value, maximum) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > maximum) throw new Error('Invalid integer parameter');
  return number;
}

function normalizePortHopping(value) {
  if (value === undefined || value === null || String(value).trim() === '') return '';
  return String(value).split(/[;,]/).map(range => {
    const parts = range.trim().split('-');
    if (parts.length > 2) throw new Error('Invalid port-hopping range');
    const start = normalizePort(parts[0]);
    if (parts.length === 1) return String(start);
    const end = normalizePort(parts[1]);
    if (end < start) throw new Error('Invalid port-hopping range');
    return `${start}-${end}`;
  }).join(';');
}

function normalizeBandwidth(value) {
  const text = String(value).trim().replace(/\s*(?:mbps|mbit\/s)$/i, '').trim();
  const bandwidth = Number(text);
  if (!Number.isFinite(bandwidth) || bandwidth <= 0) throw new Error('Invalid Hysteria 2 download bandwidth');
  return String(bandwidth);
}

function normalizeHeaders(value) {
  const headers = Array.isArray(value)
    ? value
    : value && typeof value === 'object'
      ? Object.entries(value).map(([name, headerValue]) => `${name}:${headerValue}`)
      : [value];
  return safeText(headers.map(header => String(header).trim()).join(';'));
}

function formatWireGuardReserved(value) {
  const bytes = (Array.isArray(value) ? value : String(value).split(',')).map(item => Number(item));
  if (bytes.length !== 3 || bytes.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new Error('WireGuard reserved data must contain three bytes');
  }
  return bytes.join('/');
}

function parseClashProxy(proxy, index) {
  if (!proxy || typeof proxy !== 'object' || Array.isArray(proxy)) throw new Error('Invalid proxy');
  const protocol = String(proxy.type ?? '').toLowerCase();
  if (protocol === 'wireguard') return parseClashWireGuard(proxy, index);
  const host = normalizeHost(proxy.server);
  const port = normalizePort(proxy.port);
  const params = [];

  if (protocol === 'ss' || protocol === 'shadowsocks') {
    const method = safeText(proxy.cipher).toLowerCase();
    if (!SUPPORTED_SS_METHODS.has(method)) throw new Error('Unsupported Shadowsocks encryption method');
    params.push(['encrypt-method', method], ['password', safeText(proxy.password)], ['udp-relay', 'true']);
    if (proxy.plugin) {
      const plugin = String(proxy.plugin);
      const options = proxy['plugin-opts'] ?? {};
      if (!['obfs', 'obfs-local', 'simple-obfs'].includes(plugin) || !['http', 'tls'].includes(String(options.mode))) throw new Error('Unsupported Shadowsocks plugin');
      params.push(['obfs', String(options.mode)]);
      if (options.host) params.push(['obfs-host', normalizeHost(options.host)]);
    }
    return makeProxy(proxy.name, 'ss', host, port, params);
  }

  if (protocol === 'anytls') {
    params.push(['password', safeText(proxy.password)]);
    if (proxy.sni || proxy.servername) params.push(['sni', normalizeHost(proxy.sni || proxy.servername)]);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    if (proxy.reuse !== undefined) params.push(['reuse', String(parseBooleanParam(proxy.reuse))]);
    const alpn = firstAlpn(proxy.alpn);
    if (alpn) params.push(['alpn', alpn]);
    return makeProxy(proxy.name, 'anytls', host, port, params);
  }

  if (protocol === 'snell') {
    const version = Number(proxy.version ?? 1);
    if (!Number.isInteger(version) || version < 1 || version > 6) throw new Error('Unsupported Snell version');
    params.push(['psk', safeText(proxy.psk || proxy.password)], ['version', String(version)]);

    const obfsOptions = proxy['obfs-opts'] ?? {};
    const obfs = String(proxy.obfs || obfsOptions.mode || '').toLowerCase();
    if (obfs) {
      if (!['http', 'tls'].includes(obfs) || (version >= 4 && obfs !== 'http') || version === 6) {
        throw new Error('Unsupported Snell obfuscation for this version');
      }
      params.push(['obfs', obfs]);
      if (obfsOptions.host) params.push(['obfs-host', normalizeHost(obfsOptions.host)]);
      if (obfsOptions.uri) params.push(['obfs-uri', safeText(obfsOptions.uri)]);
    }
    if (proxy['udp-port']) params.push(['udp-port', String(normalizePort(proxy['udp-port']))]);
    if (proxy.reuse !== undefined) params.push(['reuse', String(parseBooleanParam(proxy.reuse))]);
    if (proxy.mode) {
      const mode = String(proxy.mode).toLowerCase();
      if (version !== 6 || !['default', 'unshaped', 'unsafe-raw'].includes(mode)) throw new Error('Unsupported Snell mode');
      if (mode !== 'default') params.push(['mode', mode]);
    }
    return makeProxy(proxy.name, 'snell', host, port, params);
  }

  if (protocol === 'masque') {
    if (proxy.username) params.push(['username', safeText(proxy.username)]);
    if (proxy.password) params.push(['password', safeText(proxy.password)]);
    if (proxy.sni || proxy.servername) params.push(['sni', normalizeHost(proxy.sni || proxy.servername)]);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    const portHopping = normalizePortHopping(proxy['port-hopping'] || proxy.ports || proxy.mport);
    if (portHopping) params.push(['port-hopping', portHopping]);
    if (proxy['port-hopping-interval']) params.push(['port-hopping-interval', String(normalizePositiveInteger(proxy['port-hopping-interval'], 86400))]);
    const alpn = firstAlpn(proxy.alpn);
    if (alpn) params.push(['alpn', alpn]);
    return makeProxy(proxy.name, 'masque', host, port, params);
  }

  if (protocol === 'trust-tunnel' || protocol === 'trust_tunnel') {
    params.push(['username', safeText(proxy.username)], ['password', safeText(proxy.password)]);
    if (proxy.sni || proxy.servername) params.push(['sni', normalizeHost(proxy.sni || proxy.servername)]);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    if (truthy(proxy.h3)) params.push(['h3', 'true']);
    if (proxy['max-streams']) params.push(['max-streams', String(normalizePositiveInteger(proxy['max-streams'], 65535))]);
    if (proxy.headers) params.push(['headers', normalizeHeaders(proxy.headers)]);
    if (proxy['client-random-auth-key']) params.push(['client-random-auth-key', safeText(proxy['client-random-auth-key'])]);
    return makeProxy(proxy.name, 'trust-tunnel', host, port, params);
  }

  if (protocol === 'ssh') {
    if (!proxy.username || !proxy.password) throw new Error('SSH proxy conversion requires username and password');
    params.push(['username', safeText(proxy.username)], ['password', safeText(proxy.password)]);
    if (proxy['idle-timeout']) params.push(['idle-timeout', String(normalizePositiveInteger(proxy['idle-timeout'], 86400))]);
    if (proxy['server-fingerprint']) params.push(['server-fingerprint', safeText(proxy['server-fingerprint'])]);
    return makeProxy(proxy.name, 'ssh', host, port, params);
  }

  if (protocol === 'h2-connect') {
    if (proxy.username) params.push(['username', safeText(proxy.username)]);
    if (proxy.password) params.push(['password', safeText(proxy.password)]);
    if (proxy.sni || proxy.servername) params.push(['sni', normalizeHost(proxy.sni || proxy.servername)]);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    if (proxy.headers) params.push(['headers', normalizeHeaders(proxy.headers)]);
    if (proxy['max-streams']) params.push(['max-streams', String(normalizePositiveInteger(proxy['max-streams'], 65535))]);
    if (truthy(proxy['udp-relay'])) params.push(['udp-relay', 'true']);
    return makeProxy(proxy.name, 'h2-connect', host, port, params);
  }

  if (protocol === 'vmess') {
    const network = String(proxy.network || 'tcp').toLowerCase();
    if (!['tcp', 'ws'].includes(network)) throw new Error('Unsupported VMess transport');
    params.push(['username', safeText(proxy.uuid)], ['vmess-aead', Number(proxy.alterId ?? 0) === 0 ? 'true' : 'false']);
    addVmessEncryption(params, proxy.cipher);
    if (truthy(proxy.tls)) params.push(['tls', 'true']);
    const sni = proxy.servername || (truthy(proxy.tls) && network === 'tcp' ? proxy['ws-opts']?.headers?.Host : '');
    if (sni) params.push(['sni', normalizeHost(sni)]);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    if (network === 'ws') {
      params.push(['ws', 'true']);
      const ws = proxy['ws-opts'] ?? {};
      if (ws.path) params.push(['ws-path', safeText(ws.path)]);
      const wsHost = ws.headers?.Host || ws.headers?.host;
      if (wsHost) params.push(['ws-headers', `Host:${normalizeHost(wsHost)}`]);
    }
    const alpn = firstAlpn(proxy.alpn);
    if (alpn) params.push(['alpn', alpn]);
    return makeProxy(proxy.name, 'vmess', host, port, params);
  }

  if (protocol === 'trojan') {
    const network = String(proxy.network || 'tcp').toLowerCase();
    if (!['tcp', 'ws'].includes(network)) throw new Error('Unsupported Trojan transport');
    params.push(['password', safeText(proxy.password)]);
    if (proxy.sni || proxy.servername) params.push(['sni', normalizeHost(proxy.sni || proxy.servername)]);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    if (network === 'ws') {
      const ws = proxy['ws-opts'] ?? {};
      addWebSocketParams(params, ws.path, ws.headers?.Host || ws.headers?.host);
    }
    const alpn = firstAlpn(proxy.alpn);
    if (alpn) params.push(['alpn', alpn]);
    return makeProxy(proxy.name, 'trojan', host, port, params);
  }

  if (protocol === 'hysteria2' || protocol === 'hy2') {
    params.push(['password', safeText(proxy.password || proxy.auth || proxy['auth-str'] || '')]);
    if (proxy.sni || proxy.servername) params.push(['sni', normalizeHost(proxy.sni || proxy.servername)]);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    const alpn = firstAlpn(proxy.alpn);
    if (alpn) params.push(['alpn', alpn]);
    if (proxy.obfs) {
      const obfs = String(proxy.obfs).toLowerCase();
      if (!['salamander', 'gecko'].includes(obfs)) throw new Error('Unsupported Hysteria2 obfuscation');
      const obfsPassword = proxy['obfs-password'] || proxy.obfsPassword;
      if (!obfsPassword) throw new Error('Missing Hysteria2 obfuscation password');
      params.push([obfs === 'salamander' ? 'salamander-password' : 'gecko-password', safeText(obfsPassword)]);
    }
    const portHopping = normalizePortHopping(proxy['port-hopping'] || proxy.ports || proxy.mport);
    if (portHopping) params.push(['port-hopping', portHopping]);
    const hoppingInterval = proxy['port-hopping-interval'] || proxy['hop-interval'] || proxy.hop_interval;
    if (hoppingInterval) params.push(['port-hopping-interval', String(normalizePositiveInteger(hoppingInterval, 86400))]);
    const downloadBandwidth = proxy['download-bandwidth'] || proxy.down || proxy.downmbps;
    if (downloadBandwidth) params.push(['download-bandwidth', normalizeBandwidth(downloadBandwidth)]);
    return makeProxy(proxy.name, 'hysteria2', host, port, params);
  }

  if (protocol === 'tuic') {
    let proxyType;
    if (proxy.uuid && proxy.password) {
      params.push(['uuid', safeText(proxy.uuid)], ['password', safeText(proxy.password)]);
      proxyType = 'tuic-v5';
    } else if (proxy.token) {
      params.push(['token', safeText(proxy.token)]);
      proxyType = 'tuic';
    } else throw new Error('Missing TUIC credentials');
    if (proxy.sni || proxy.servername) params.push(['sni', normalizeHost(proxy.sni || proxy.servername)]);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    const alpn = firstAlpn(proxy.alpn);
    if (alpn) params.push(['alpn', alpn]);
    const portHopping = normalizePortHopping(proxy['port-hopping'] || proxy.ports || proxy.mport);
    if (portHopping) params.push(['port-hopping', portHopping]);
    const hoppingInterval = proxy['port-hopping-interval'] || proxy['hop-interval'] || proxy.hop_interval;
    if (hoppingInterval) params.push(['port-hopping-interval', String(normalizePositiveInteger(hoppingInterval, 86400))]);
    return makeProxy(proxy.name, proxyType, host, port, params);
  }

  if (protocol === 'http' || protocol === 'socks5' || protocol === 'socks5-tls') {
    if (proxy.username) params.push(['username', safeText(proxy.username)]);
    if (proxy.password) params.push(['password', safeText(proxy.password)]);
    if (protocol === 'http' && truthy(proxy.tls)) params.push(['tls', 'true']);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    if ((protocol === 'socks5' || protocol === 'socks5-tls') && truthy(proxy['udp-relay'])) params.push(['udp-relay', 'true']);
    const outputProtocol = protocol === 'socks5' && truthy(proxy.tls) ? 'socks5-tls' : protocol;
    return makeProxy(proxy.name, outputProtocol, host, port, params);
  }

  return null;
}

function addWebSocketParams(params, path, host) {
  params.push(['ws', 'true']);
  const normalizedPath = path ? safeText(path) : '';
  if (normalizedPath && normalizedPath !== '/') params.push(['ws-path', normalizedPath]);
  if (host) params.push(['ws-headers', `Host:${normalizeHost(host)}`]);
}

function addVmessEncryption(params, value) {
  const cipher = String(value || 'auto').toLowerCase();
  if (cipher === 'auto' || cipher === 'aes-128-gcm') return;
  if (cipher === 'chacha20-poly1305' || cipher === 'chacha20-ietf-poly1305') {
    params.push(['encrypt-method', 'chacha20-ietf-poly1305']);
    return;
  }
  throw new Error('Unsupported VMess encryption method');
}

function supportedShadowsocksMethod(value) {
  const method = safeText(value).toLowerCase();
  if (!SUPPORTED_SS_METHODS.has(method)) throw new Error('Unsupported Shadowsocks encryption method');
  return method;
}

function makeProxy(name, type, host, port, params) {
  const validParams = params.filter(([, value]) => value !== undefined && value !== null && String(value) !== '');
  return {
    name: safeName(name),
    type,
    host: normalizeHost(host),
    port: normalizePort(port),
    params: validParams,
  };
}

function assignUniqueNames(entries) {
  const counts = new Map();
  return entries.map((entry, index) => {
    const base = entry.name || `Node-${index + 1}`;
    const count = (counts.get(base) ?? 0) + 1;
    counts.set(base, count);
    return { ...entry, name: count === 1 ? base : `${base}-${count}` };
  });
}

function formatProxy(entry) {
  if (entry.type === 'wireguard') {
    return `${entry.name} = wireguard, section-name=${formatValue(entry.sectionName)}`;
  }
  const params = entry.params.map(([key, value]) => `${key}=${formatValue(value)}`);
  return `${entry.name} = ${entry.type}, ${entry.host}, ${entry.port}${params.length ? `, ${params.join(', ')}` : ''}`;
}

function formatValue(value) {
  const text = safeText(value);
  if (SAFE_VALUE.test(text)) return text;
  return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function safeText(value) {
  const text = String(value ?? '').trim();
  if (!text || /[\r\n\u0000]/.test(text)) throw new Error('Invalid config value');
  return text;
}

function safeName(value) {
  const text = String(value ?? '')
    .replace(/[\r\n\u0000]/g, ' ')
    .replace(/[^\p{L}\p{N}\p{M}\p{Extended_Pictographic}\p{Regional_Indicator}\p{Emoji_Modifier}\u200D\u{E0020}-\u{E007F}._ ()+-]/gu, '_')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
  return text || '';
}

function normalizeHost(value) {
  let host = String(value ?? '').trim();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (!host || /[\s,;#\/?@]/.test(host)) throw new Error('Invalid server host');
  if (isIP(host)) return host.toLowerCase();

  const ascii = domainToASCII(host).toLowerCase();
  const labels = ascii.split('.');
  if (!ascii || ascii.length > 253 || !/^[a-z0-9.-]+$/.test(ascii) || labels.some(label => !label || label.startsWith('-') || label.endsWith('-'))) {
    throw new Error('Invalid server host');
  }
  return ascii;
}

function normalizePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid server port');
  return port;
}

function parseHostPort(authority) {
  const url = new URL(`ss://user@${authority}`);
  return { host: normalizeHost(url.hostname), port: normalizePort(url.port) };
}

function decodeBase64(value) {
  const text = String(value ?? '').trim();
  const normalized = text.replace(/-/g, '+').replace(/_/g, '/');
  const decoded = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(normalized, 'base64'));
  if (!decoded) throw new Error('Invalid Base64 data');
  return decoded;
}

function maybeBase64(value) {
  if (!/^[A-Za-z0-9_+/=-]+$/.test(value) || value.length < 8) return null;
  try {
    return decodeBase64(value);
  } catch {
    return null;
  }
}

function decodePart(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function truthy(value) {
  return value === true || value === 1 || /^(?:true|1|yes|tls)$/i.test(String(value ?? ''));
}

function isTruthyParam(value) {
  return truthy(value);
}

function parseBooleanParam(value) {
  if (/^(?:true|1|yes)$/i.test(String(value ?? ''))) return true;
  if (/^(?:false|0|no)$/i.test(String(value ?? ''))) return false;
  throw new Error('Invalid boolean parameter');
}

function firstAlpn(value) {
  if (Array.isArray(value)) return value.length ? safeText(value[0]) : '';
  if (typeof value !== 'string' || !value.trim()) return '';
  return safeText(value.split(',')[0].trim());
}

function bump(counts, key) {
  counts[key] = (counts[key] ?? 0) + 1;
}
