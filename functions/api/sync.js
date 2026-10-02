const MIN_TOKEN_LEN = 8;

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Sync-Token',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...corsHeaders(request),
    },
  });
}

async function tokenKey(token) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(token)
  );
  const hex = [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `aca:${hex}`;
}

function readToken(request) {
  const header = (request.headers.get('X-Sync-Token') || '').trim();
  if (header) return header;
  try {
    const url = new URL(request.url);
    return (url.searchParams.get('token') || '').trim();
  } catch {
    return '';
  }
}

function validateToken(token) {
  if (!token || token.length < MIN_TOKEN_LEN) {
    return '同步口令至少 8 位';
  }
  if (token.length > 128) {
    return '同步口令过长';
  }
  return null;
}

function sanitizePayload(body) {
  const wrong = Array.isArray(body.wrong)
    ? body.wrong.filter((x) => Number.isFinite(Number(x))).map(Number)
    : [];
  const fav = Array.isArray(body.fav)
    ? body.fav.filter((x) => Number.isFinite(Number(x))).map(Number)
    : [];
  const progress =
    body.progress && typeof body.progress === 'object' ? body.progress : null;
  const updatedAt = Number(body.updatedAt) || Date.now();
  return { wrong, fav, progress, updatedAt };
}

export async function onRequestOptions(context) {
  return new Response(null, {
    status: 204,
    headers: corsHeaders(context.request),
  });
}

export async function onRequestGet(context) {
  const { request, env } = context;
  if (!env.PROGRESS) {
    return json({ error: 'KV 未绑定，请在 Cloudflare 配置 PROGRESS' }, 500, request);
  }
  const token = readToken(request);
  const err = validateToken(token);
  if (err) return json({ error: err }, 400, request);

  const key = await tokenKey(token);
  const raw = await env.PROGRESS.get(key);
  if (!raw) {
    return json({ exists: false, wrong: [], fav: [], progress: null, updatedAt: 0 }, 200, request);
  }
  try {
    const data = JSON.parse(raw);
    return json({ exists: true, ...sanitizePayload(data) }, 200, request);
  } catch {
    return json({ error: '云端数据损坏' }, 500, request);
  }
}

export async function onRequestPut(context) {
  const { request, env } = context;
  if (!env.PROGRESS) {
    return json({ error: 'KV 未绑定，请在 Cloudflare 配置 PROGRESS' }, 500, request);
  }
  const token = readToken(request);
  const err = validateToken(token);
  if (err) return json({ error: err }, 400, request);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: '请求体必须是 JSON' }, 400, request);
  }

  const payload = sanitizePayload(body);
  const key = await tokenKey(token);

  const existingRaw = await env.PROGRESS.get(key);
  if (existingRaw) {
    try {
      const existing = JSON.parse(existingRaw);
      const remoteAt = Number(existing.updatedAt) || 0;
      if (remoteAt > payload.updatedAt) {
        return json(
          {
            ok: false,
            conflict: true,
            ...sanitizePayload(existing),
          },
          409,
          request
        );
      }
    } catch {
      /* overwrite corrupt data */
    }
  }

  await env.PROGRESS.put(key, JSON.stringify(payload));
  return json({ ok: true, updatedAt: payload.updatedAt }, 200, request);
}
