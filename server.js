import { createServer } from 'node:http';
import { convertSubscription, ConversionError } from './src/convert.js';
import { fetchSubscription, SourceFetchError } from './src/fetch-source.js';

const port = Number(process.env.PORT || 8080);
const host = process.env.HOST || '0.0.0.0';

const server = createServer(async (request, response) => {
  let requestUrl;
  try {
    requestUrl = new URL(request.url || '/', 'http://service.local');
  } catch {
    return sendText(response, 400, 'Malformed request URL.');
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return sendText(response, 405, 'Method not allowed.');
  }

  if (requestUrl.pathname === '/healthz') {
    response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    return response.end('ok\n');
  }

  const isHome = requestUrl.pathname === '/' || requestUrl.pathname === '/index.html';
  const isNodeList = requestUrl.pathname === '/node' || requestUrl.pathname === '/sub' || requestUrl.pathname === '/convert';

  if (isHome && !requestUrl.searchParams.has('url')) {
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    });
    return response.end(indexHtml());
  }

  if (!isHome && !isNodeList) {
    return sendText(response, 404, 'Not found. Use /?url=<subscription-url> for a full config or /node?url=<subscription-url> for nodes.');
  }

  const source = requestUrl.searchParams.get('url');
  if (!source) return sendText(response, 400, 'Missing required query parameter: url');

  try {
    const body = await fetchSubscription(source);
    const result = convertSubscription(body);
    const fullConfig = isHome;
    const skippedSummary = Object.entries(result.skippedByProtocol)
      .map(([protocol, count]) => `${String(protocol).replace(/[^a-z0-9_-]/gi, '_').slice(0, 32)}=${count}`)
      .join(', ')
      .slice(0, 256);

    response.writeHead(200, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'content-disposition': `inline; filename="${fullConfig ? 'surge.conf' : 'surge-proxies.conf'}"`,
      'x-content-type-options': 'nosniff',
      'x-conversion-output': fullConfig ? 'full-config' : 'nodes',
      'x-conversion-total': String(result.total),
      'x-conversion-converted': String(result.converted),
      'x-conversion-skipped': String(result.skipped),
      ...(skippedSummary ? { 'x-conversion-skipped-protocols': skippedSummary } : {}),
    });
    return response.end(request.method === 'HEAD' ? undefined : fullConfig ? result.fullConfig : result.config);
  } catch (error) {
    const status = error instanceof SourceFetchError || error instanceof ConversionError ? error.status : 500;
    const message = error instanceof SourceFetchError || error instanceof ConversionError
      ? error.message
      : 'Conversion failed.';
    return sendText(response, status, message);
  }
});

server.listen(port, host, () => {
  console.log(`Surge node converter listening on ${host}:${port}`);
});

function sendText(response, status, message) {
  response.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  });
  response.end(`${message}\n`);
}

function indexHtml() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Surge 节点转换器</title>
  <style>
    :root { color-scheme: light; --ink:#172826; --muted:#607370; --paper:#f5f4ec; --card:#fffef9; --line:#d9ded3; --green:#17694f; --lime:#c6e36b; --orange:#e97747; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; color:var(--ink); background:radial-gradient(ellipse at 87% 9%, #dce7b9 0, transparent 32%), radial-gradient(ellipse at 0% 95%, #f1d8c8 0, transparent 30%), var(--paper); font-family:ui-sans-serif, system-ui, -apple-system, "PingFang SC", "Noto Sans CJK SC", sans-serif; }
    main { width:min(840px, calc(100% - 36px)); margin:0 auto; padding:clamp(44px, 9vw, 94px) 0 52px; }
    .eyebrow { display:flex; align-items:center; gap:10px; color:var(--green); font-size:12px; font-weight:800; letter-spacing:.18em; text-transform:uppercase; }
    .dot { width:9px; height:9px; border-radius:50%; background:var(--orange); box-shadow:0 0 0 5px #e9774720; }
    h1 { max-width:700px; margin:20px 0 12px; font-size:clamp(38px, 8vw, 68px); line-height:.99; letter-spacing:-.055em; font-weight:850; }
    h1 em { color:var(--green); font-style:normal; }
    .intro { max-width:560px; margin:0; color:var(--muted); font-size:16px; line-height:1.75; }
    .panel { margin-top:36px; padding:clamp(20px, 4vw, 32px); border:1px solid #ffffffd1; border-radius:20px; background:var(--card); box-shadow:0 20px 60px #28372e12; }
    label { display:block; margin-bottom:10px; font-size:13px; font-weight:800; }
    .field { display:flex; gap:10px; }
    input { flex:1; min-width:0; padding:15px 16px; border:1px solid var(--line); border-radius:11px; color:var(--ink); background:#fbfcf6; font:inherit; font-size:14px; outline:none; transition:border-color .16s, box-shadow .16s; }
    input:focus { border-color:var(--green); box-shadow:0 0 0 4px #17694f18; }
    button { border:0; border-radius:11px; padding:0 20px; color:white; background:var(--green); font:inherit; font-size:14px; font-weight:800; cursor:pointer; transition:transform .16s, background .16s; }
    button:hover { background:#10563f; transform:translateY(-1px); }
    .hint { margin:10px 0 0; color:var(--muted); font-size:12px; line-height:1.6; }
    .result { display:none; margin-top:24px; padding-top:22px; border-top:1px solid var(--line); }
    .result.show { display:block; animation:rise .28s ease-out both; }
    .result-title { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:9px; font-size:13px; font-weight:800; }
    .copy { min-height:36px; padding:0 13px; color:var(--green); background:#e8f0dc; font-size:12px; }
    .copy:hover { color:white; }
    code { display:block; overflow-wrap:anywhere; padding:14px; border-radius:10px; color:#dce8cd; background:#172826; font:12px/1.65 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .usage { margin:12px 0 0; color:var(--muted); font-size:12px; line-height:1.65; }
    .foot { display:flex; gap:14px; align-items:flex-start; margin:22px 4px 0; color:var(--muted); font-size:12px; line-height:1.7; }
    .badge { flex:none; padding:4px 8px; border:1px solid #b7c6a0; border-radius:20px; color:var(--green); font-size:10px; font-weight:800; letter-spacing:.08em; }
    @keyframes rise { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
    @media (max-width:560px) { main { width:min(100% - 24px, 840px); padding-top:40px; } .field { flex-direction:column; } input { padding:14px; } button { min-height:48px; } .panel { border-radius:16px; } }
    @media (prefers-reduced-motion:reduce) { *, *::before, *::after { animation-duration:.01ms !important; transition-duration:.01ms !important; } }
  </style>
</head>
<body>
  <main>
    <div class="eyebrow"><span class="dot"></span>Share link → Surge</div>
    <h1>只留节点，<em>其余交给 Surge。</em></h1>
    <p class="intro">粘贴订阅地址，生成可持续更新的最小完整 Surge 配置。根路径返回配置文件；如果只需要节点列表，可使用同一个地址的 <code style="display:inline;padding:2px 5px;font-size:11px">/node</code> 路径。</p>
    <section class="panel">
      <form id="form">
        <label for="source">订阅地址</label>
        <div class="field">
          <input id="source" name="url" type="text" inputmode="url" placeholder="https://example.com/subscription..." autocomplete="off" required>
          <button type="submit">生成转换链接 <span aria-hidden="true">↗</span></button>
        </div>
        <p class="hint">链接会包含原订阅地址，请像密码一样妥善保管；托管平台的访问日志策略以平台设置为准。</p>
      </form>
      <div class="result" id="result" aria-live="polite">
        <div class="result-title"><span>完整 Surge 配置链接</span><button class="copy" id="copy" type="button">复制链接</button></div>
        <code id="link"></code>
        <p class="usage">根路径返回 <code style="display:inline;padding:2px 5px;font-size:11px">[General]</code>、<code style="display:inline;padding:2px 5px;font-size:11px">[Proxy]</code>、<code style="display:inline;padding:2px 5px;font-size:11px">[Proxy Group]</code> 和 <code style="display:inline;padding:2px 5px;font-size:11px">[Rule]</code>。只需节点时，将链接中的路径改为 <code style="display:inline;padding:2px 5px;font-size:11px">/node</code>。</p>
      </div>
    </section>
    <div class="foot"><span class="badge">支持</span><span>Shadowsocks、VMess、Trojan、Hysteria2、TUIC，以及 Clash 订阅中的对应节点。VLESS / SSR 不是 Surge 可直接使用的协议，会被跳过；若订阅只有不支持的节点，会返回说明而不生成空配置。</span></div>
  </main>
  <script>
    const form = document.getElementById('form');
    const source = document.getElementById('source');
    const result = document.getElementById('result');
    const output = document.getElementById('link');
    form.addEventListener('submit', event => {
      event.preventDefault();
      const value = source.value.trim();
      const target = new URL('/', window.location.origin);
      target.searchParams.set('url', value);
      output.textContent = target.href;
      result.classList.add('show');
    });
    document.getElementById('copy').addEventListener('click', async event => {
      try {
        await navigator.clipboard.writeText(output.textContent);
        event.currentTarget.textContent = '已复制';
        setTimeout(() => { event.currentTarget.textContent = '复制链接'; }, 1600);
      } catch {
        window.prompt('复制以下链接：', output.textContent);
      }
    });
  </script>
</body>
</html>`;
}
