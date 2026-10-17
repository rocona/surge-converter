import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { Agent } from 'undici';

const MAX_SOURCE_URL_LENGTH = 4096;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_REDIRECTS = 3;
const REQUEST_TIMEOUT_MS = 15000;

const blockedV4 = new BlockList();
for (const [subnet, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) blockedV4.addSubnet(subnet, prefix, 'ipv4');

const blockedV6 = new BlockList();
for (const [subnet, prefix] of [
  ['::', 128], ['::1', 128], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48],
  ['100::', 64], ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7],
  ['fe80::', 10], ['ff00::', 8],
]) blockedV6.addSubnet(subnet, prefix, 'ipv6');

export class SourceFetchError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = 'SourceFetchError';
    this.status = status;
  }
}

export function isShareLink(value) {
  return /^(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic):\/\//i.test(value);
}

export function validateSourceUrl(value) {
  const text = String(value ?? '').trim();
  if (!text || text.length > MAX_SOURCE_URL_LENGTH) throw new SourceFetchError('Missing or oversized url parameter.');
  if (isShareLink(text)) return { direct: text };

  let url;
  try {
    url = new URL(text);
  } catch {
    throw new SourceFetchError('url must be an http(s) subscription URL or a supported share link.');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new SourceFetchError('Only http(s) subscription URLs are allowed.');
  if (url.username || url.password) throw new SourceFetchError('Credentials embedded in the source URL are not accepted.');
  if (!url.hostname) throw new SourceFetchError('The source URL must include a hostname.');
  assertNotLocalHostname(url.hostname);
  return { url };
}

export async function fetchSubscription(inputUrl) {
  const checked = validateSourceUrl(inputUrl);
  if (checked.direct) return checked.direct;

  let currentUrl = checked.url;
  for (let redirect = 0; redirect <= MAX_REDIRECTS; redirect += 1) {
    assertNotLocalHostname(currentUrl.hostname);
    const addresses = await resolvePublicAddresses(currentUrl.hostname);
    const dispatcher = new Agent({
      connect: {
        lookup(_hostname, options, callback) {
          if (options?.all) callback(null, addresses);
          else callback(null, addresses[0].address, addresses[0].family);
        },
      },
    });

    try {
      const response = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: {
          accept: 'text/plain, application/yaml, application/x-yaml, */*;q=0.5',
          'user-agent': 'Surge-Node-Converter/1.0',
        },
        dispatcher,
      });

      if (isRedirect(response.status)) {
        const location = response.headers.get('location');
        await response.body?.cancel();
        if (!location || redirect === MAX_REDIRECTS) throw new SourceFetchError('The source returned too many redirects.', 502);
        const next = new URL(location, currentUrl);
        if (currentUrl.protocol === 'https:' && next.protocol !== 'https:') {
          throw new SourceFetchError('Refusing an insecure redirect from https to http.', 502);
        }
        const validated = validateSourceUrl(next.href);
        if (validated.direct) throw new SourceFetchError('The source redirected to an unsupported URL type.', 502);
        currentUrl = validated.url;
        continue;
      }

      if (!response.ok) {
        await response.body?.cancel();
        throw new SourceFetchError(`Source server returned HTTP ${response.status}.`, 502);
      }

      const declaredLength = Number(response.headers.get('content-length'));
      if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
        await response.body?.cancel();
        throw new SourceFetchError('The source response exceeds the 2 MiB limit.', 413);
      }
      return await readLimitedText(response);
    } catch (error) {
      if (error instanceof SourceFetchError) throw error;
      throw new SourceFetchError('Could not safely fetch the source URL (timeout, DNS, TLS, or network error).', 502);
    } finally {
      await dispatcher.close().catch(() => {});
    }
  }

  throw new SourceFetchError('Could not fetch the source URL.', 502);
}

async function resolvePublicAddresses(hostname) {
  const host = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  const family = isIP(host);
  let addresses;
  if (family) {
    addresses = [{ address: host, family }];
  } else {
    try {
      addresses = await lookup(host, { all: true, verbatim: true });
    } catch {
      throw new SourceFetchError('The source hostname could not be resolved.', 502);
    }
  }
  if (!addresses.length || addresses.some(({ address, family: version }) => !isPublicAddress(address, version))) {
    throw new SourceFetchError('The source hostname must resolve only to public IP addresses.');
  }
  return addresses;
}

function isPublicAddress(address, family = isIP(address)) {
  if (family === 4) return !blockedV4.check(address, 'ipv4');
  if (family === 6) return !blockedV6.check(address, 'ipv6');
  return false;
}

function assertNotLocalHostname(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new SourceFetchError('Local and internal hostnames are not allowed.');
  }
}

async function readLimitedText(response) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new SourceFetchError('The source response exceeds the 2 MiB limit.', 413);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(Buffer.concat(chunks));
}

function isRedirect(status) {
  return [301, 302, 303, 307, 308].includes(status);
}
