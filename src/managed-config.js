export function buildManagedConfigUrl({ protocol, host, pathname = '/', search = '' } = {}) {
  const scheme = protocol === 'https' ? 'https' : 'http';
  const authority = String(host ?? '').trim();
  if (!authority) throw new Error('A public host is required for a managed config URL.');

  const path = pathname === '/' ? '' : String(pathname || '');
  return `${scheme}://${authority}${path}${search || ''}`;
}

export function prependManagedConfig(config, endpoint, { interval = 43200, strict = true } = {}) {
  return `#!MANAGED-CONFIG ${endpoint} interval=${interval} strict=${strict}\n${config}`;
}
