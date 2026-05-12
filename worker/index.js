function getCorsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());
  const isAllowed = allowed.includes('*') || allowed.includes(origin);
  return {
    'Access-Control-Allow-Origin': isAllowed ? origin : '',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function isValidHash(s) {
  return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
}

function isValidCiphertext(s, maxLen) {
  return typeof s === 'string' && s.length > 0 && s.length <= maxLen && /^[0-9a-f]+$/.test(s);
}

function isValidIV(s) {
  return typeof s === 'string' && /^[0-9a-f]{24}$/.test(s);
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

async function handleSend(request, env, corsHeaders) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid request' }, 400, corsHeaders);
  }

  const maxLen = parseInt(env.MAX_CIPHERTEXT_LENGTH || '131072', 10);
  const { recipient_hash, sender_hash, ciphertext, iv } = body;

  if (
    !isValidHash(recipient_hash) ||
    !isValidHash(sender_hash) ||
    !isValidCiphertext(ciphertext, maxLen) ||
    !isValidIV(iv)
  ) {
    return json({ error: 'Invalid request' }, 400, corsHeaders);
  }

  const result = await env.DB.prepare(
    'INSERT INTO envelopes (recipient_hash, sender_hash, ciphertext, iv) VALUES (?, ?, ?, ?)'
  )
    .bind(recipient_hash, sender_hash, ciphertext, iv)
    .run();

  return json({ ok: true, id: result.meta.last_row_id }, 201, corsHeaders);
}

async function handleSync(request, env, corsHeaders) {
  const url = new URL(request.url);
  const forHash = url.searchParams.get('for');
  const sinceRaw = url.searchParams.get('since') ?? '0';

  const since = parseInt(sinceRaw, 10);

  if (!isValidHash(forHash) || !Number.isInteger(since) || since < 0) {
    return json({ error: 'Invalid request' }, 400, corsHeaders);
  }

  const { results } = await env.DB.prepare(
    'SELECT id, sender_hash, ciphertext, iv, created_at FROM envelopes WHERE recipient_hash = ? AND created_at > ? ORDER BY created_at ASC LIMIT 50'
  )
    .bind(forHash, since)
    .all();

  const envelopes = results.map(row => ({
    id: row.id,
    senderHash: row.sender_hash,
    ciphertext: row.ciphertext,
    iv: row.iv,
    createdAt: row.created_at,
  }));

  return json({ envelopes }, 200, corsHeaders);
}

export default {
  async fetch(request, env, ctx) {
    const corsHeaders = getCorsHeaders(request, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === '/api/send' && request.method === 'POST') {
        return await handleSend(request, env, corsHeaders);
      } else if (url.pathname === '/api/sync' && request.method === 'GET') {
        return await handleSync(request, env, corsHeaders);
      } else if (url.pathname === '/api/send' || url.pathname === '/api/sync') {
        return json({ error: 'Method not allowed' }, 405, corsHeaders);
      } else {
        return json({ error: 'Not found' }, 404, corsHeaders);
      }
    } catch (err) {
      return json({ error: 'Internal server error' }, 500, corsHeaders);
    }
  },
};
