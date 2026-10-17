import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { parse as parseYaml } from 'yaml';

const URI_PATTERN = /(?:ssr?|vmess|vless|trojan|hysteria2|hy2|tuic):\/\/[^\s<>"']+/gi;
const SAFE_VALUE = /^[A-Za-z0-9._~:/+@!$%&*()\[\]-]+$/;

export function convertSubscription(body) {
  const raw = String(body ?? '').replace(/^\uFEFF/, '').trim();
  if (!raw) throw new ConversionError('The source returned an empty subscription.', 422);

  const candidates = [raw];
  const decoded = decodeBase64Subscription(raw);
  if (decoded && decoded !== raw) candidates.push(decoded);

  for (const text of candidates) {
    const proxies = parseClashProxies(text);
    if (proxies) return convertClashProxies(proxies);

    const uris = text.match(URI_PATTERN) ?? [];
    if (uris.length) return convertShareLinks(uris);
  }

  throw new ConversionError('Could not find supported share links or a Clash proxies list in the source.', 422);
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

  for (const proxy of proxies) {
    const protocol = String(proxy?.type ?? 'unknown').toLowerCase();
    try {
      const entry = parseClashProxy(proxy);
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

  return {
    config: named.map(formatProxy).join('\n') + '\n',
    fullConfig: formatSurgeConfig(named),
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
  if (protocol === 'ssr' || protocol === 'vless') return null;
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
    ['encrypt-method', safeText(method)],
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
  return makeProxy(decodePart(url.hash.slice(1)), proxyType, normalizeHost(url.hostname), normalizePort(url.port), params);
}

function parseClashProxy(proxy) {
  if (!proxy || typeof proxy !== 'object' || Array.isArray(proxy)) throw new Error('Invalid proxy');
  const protocol = String(proxy.type ?? '').toLowerCase();
  const host = normalizeHost(proxy.server);
  const port = normalizePort(proxy.port);
  const params = [];

  if (protocol === 'ss' || protocol === 'shadowsocks') {
    params.push(['encrypt-method', safeText(proxy.cipher)], ['password', safeText(proxy.password)], ['udp-relay', 'true']);
    if (proxy.plugin) {
      const plugin = String(proxy.plugin);
      const options = proxy['plugin-opts'] ?? {};
      if (!['obfs', 'obfs-local', 'simple-obfs'].includes(plugin) || !['http', 'tls'].includes(String(options.mode))) throw new Error('Unsupported Shadowsocks plugin');
      params.push(['obfs', String(options.mode)]);
      if (options.host) params.push(['obfs-host', normalizeHost(options.host)]);
    }
    return makeProxy(proxy.name, 'ss', host, port, params);
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
    return makeProxy(proxy.name, proxyType, host, port, params);
  }

  if (protocol === 'http' || protocol === 'socks5') {
    if (proxy.username) params.push(['username', safeText(proxy.username)]);
    if (proxy.password) params.push(['password', safeText(proxy.password)]);
    if (truthy(proxy.tls)) params.push(['tls', 'true']);
    if (truthy(proxy['skip-cert-verify'])) params.push(['skip-cert-verify', 'true']);
    return makeProxy(proxy.name, protocol, host, port, params);
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
    .replace(/[^\p{L}\p{N}._ ()+-]/gu, '_')
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

function firstAlpn(value) {
  if (Array.isArray(value)) return value.length ? safeText(value[0]) : '';
  if (typeof value !== 'string' || !value.trim()) return '';
  return safeText(value.split(',')[0].trim());
}

function bump(counts, key) {
  counts[key] = (counts[key] ?? 0) + 1;
}
