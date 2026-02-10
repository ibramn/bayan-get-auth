import 'dotenv/config';
import express from 'express';
import { getAuth } from './authService.js';

const log = (...args) => console.log('[Server]', ...args);

const AUTH_REQUEST_TIMEOUT_MS = Number(process.env.AUTH_REQUEST_TIMEOUT_MS || 0) || 180000; // 3 min default
const BAYAN_BASE_URL = (process.env.BAYAN_BASE_URL || 'https://bayan.logisti.sa').replace(/\/$/, '');
const BAYAN_PROXY_TIMEOUT_MS = Number(process.env.BAYAN_PROXY_TIMEOUT_MS || 0) || 120000; // 2 min default

const app = express();
const PORT = process.env.PORT || 3000;

// Global handlers so the process doesn't exit silently or crash without logging
process.on('uncaughtException', (err) => {
  console.error('[Server] uncaughtException:', err?.message || err);
  console.error(err?.stack);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[Server] unhandledRejection:', reason);
});

app.use(express.json());

app.use((req, res, next) => {
  log('Request', req.method, req.path, req.ip || '-');
  const start = Date.now();
  res.once('finish', () => {
    log('Response', req.method, req.path, res.statusCode, `${Date.now() - start}ms`);
  });
  next();
});

/**
 * GET or POST /auth
 * Returns cookie and access token for Bayan (logisti.sa).
 */
app.all('/auth', async (req, res) => {
  log('/auth handler started');
  let timedOut = false;
  const timeoutId =
    AUTH_REQUEST_TIMEOUT_MS > 0
      ? setTimeout(() => {
          timedOut = true;
          if (!res.headersSent) {
            res.status(504).json({
              success: false,
              error: 'Auth request timed out',
              code: 'AUTH_TIMEOUT',
            });
          }
        }, AUTH_REQUEST_TIMEOUT_MS)
      : null;

  try {
    if (timedOut) return;
    const auth = await getAuth();
    if (timedOut || res.headersSent) return;
    clearTimeout(timeoutId);
    log('/auth success, returning cookie + token');
    res.json({
      success: true,
      cookie: auth?.cookie ?? {},
      cookieHeader: auth?.cookieHeader ?? '',
      accessToken: auth?.accessToken ?? null,
      headers: auth?.headers ?? {},
    });
  } catch (error) {
    if (timedOut || res.headersSent) return;
    clearTimeout(timeoutId);
    console.error('[Server] /auth error:', error?.message, error?.code || '');
    res.status(500).json({
      success: false,
      error: error?.message ?? 'Unknown error',
      code: error?.code ?? null,
      debugScreenshot: error?.debugScreenshot ?? null,
    });
  }
});

app.get('/health', (req, res) => {
  log('/health');
  res.json({ ok: true });
});

/**
 * Proxy all Bayan API calls through this app so .NET (and others) never call bayan.logisti.sa directly.
 * Request to /bayan/api/... → get auth, then forward to BAYAN_BASE_URL/api/... with Cookie + Bearer.
 */
app.all(['/bayan', '/bayan/*'], (req, res) => {
  proxyToBayan(req, res);
});

async function proxyToBayan(req, res) {
  const rawPathAndQuery = req.originalUrl.replace(/^\/bayan/, '') || '/';

  // Special-case: Bayan print endpoint expects POST with body { tripId: "..." } (not query param).
  // If caller sends ?tripId=..., translate it to body and remove from upstream URL.
  let pathAndQuery = rawPathAndQuery;
  let bodyOverride = null;
  try {
    const u = new URL('http://local' + rawPathAndQuery);
    if (u.pathname === '/api/consignment_notes/print/trip') {
      const tripIdQ = u.searchParams.get('tripId');
      if (tripIdQ) {
        u.searchParams.delete('tripId');
        pathAndQuery = u.pathname + (u.searchParams.toString() ? `?${u.searchParams.toString()}` : '');
        const b = req.body && typeof req.body === 'object' ? req.body : {};
        if (!b.tripId) bodyOverride = { tripId: String(tripIdQ) };
      }
    }
  } catch (_) {}

  const targetUrl = BAYAN_BASE_URL + pathAndQuery;
  log('Bayan proxy', req.method, rawPathAndQuery, bodyOverride ? '(tripId from query → body)' : '');

  const doUpstream = async (auth, attemptLabel = 'initial') => {
    const cookieHeader = auth?.cookieHeader || auth?.headers?.Cookie || auth?.headers?.cookie || '';
    const hasBearer = Boolean(auth?.accessToken);
    const cookieLen = typeof cookieHeader === 'string' ? cookieHeader.length : 0;
    const cookieCount =
      typeof cookieHeader === 'string' && cookieHeader
        ? cookieHeader.split(';').filter((p) => p.includes('=')).length
        : 0;
    log('Bayan proxy auth ready', { attempt: attemptLabel, hasBearer, cookieLen, cookieCount });

    const headers = {
      'Accept-Language': 'en-US,en;q=0.9',
      ...(auth?.headers && typeof auth.headers === 'object' ? auth.headers : {}),
    };
    if (cookieHeader) headers['Cookie'] = cookieHeader;
    if (auth?.accessToken) headers['Authorization'] = `Bearer ${auth.accessToken}`;
    headers['Accept'] = req.get('Accept') || headers['Accept'] || 'application/json, text/plain, */*';
    if (pathAndQuery.includes('/print/') && !String(headers['Accept']).includes('application/pdf')) {
      headers['Accept'] = `application/pdf, ${headers['Accept']}`;
    }

    log('Bayan proxy upstream headers', {
      attempt: attemptLabel,
      sendAuthorization: Boolean(headers['Authorization']),
      sendCookie: Boolean(headers['Cookie']),
      accept: headers['Accept'],
    });

    const opts = {
      method: req.method,
      headers,
      signal: AbortSignal.timeout(BAYAN_PROXY_TIMEOUT_MS),
    };
    const hasBody = req.method !== 'GET' && req.method !== 'HEAD' && req.body !== undefined && req.body !== null;
    if (hasBody) {
      const contentType = req.get('Content-Type') || 'application/json';
      headers['Content-Type'] = contentType;
      opts.body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    }
    if (req.method === 'GET' && req.body !== undefined && req.body !== null && Object.keys(req.body || {}).length > 0) {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(req.body);
    }
    if (bodyOverride) {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(bodyOverride);
    }

    const upstream = await fetch(targetUrl, opts);
    return upstream;
  };

  let auth;
  try {
    auth = await getAuth();
  } catch (e) {
    console.error('[Server] Bayan proxy getAuth failed:', e?.message);
    res.status(502).json({ success: false, error: 'Auth failed: ' + (e?.message ?? 'unknown') });
    return;
  }

  try {
    let upstream = await doUpstream(auth, 'initial');
    const contentType = upstream.headers.get('Content-Type') || '';
    const contentLengthHeader = upstream.headers.get('Content-Length') || '';
    const isJson = contentType.includes('application/json');
    const isBinary = contentType.includes('application/pdf') || contentType.includes('octet-stream');
    const isPrintEndpoint =
      pathAndQuery.startsWith('/api/consignment_notes/print/') || pathAndQuery.includes('/consignment_notes/print/');
    log('Bayan proxy upstream meta', {
      status: upstream.status,
      contentType,
      contentLength: contentLengthHeader,
      isBinary,
      isPrintEndpoint,
    });

    if (!upstream.ok) {
      const text = await upstream.text().catch(() => '');
      log('Bayan proxy upstream error', upstream.status, pathAndQuery, text?.slice(0, 200));
      res.status(upstream.status).set('Content-Type', contentType || 'text/plain').send(text || upstream.statusText);
      return;
    }

    if (upstream.status === 204 || contentLengthHeader === '0') {
      res.status(204).end();
      return;
    }

    // For print endpoints, always treat response as binary to avoid corrupting PDF by reading as text.
    if (isBinary || isPrintEndpoint) {
      const ab = await upstream.arrayBuffer();
      const out = Buffer.from(ab);
      const cd = upstream.headers.get('Content-Disposition');
      const ct = contentType || 'application/pdf';
      log('Bayan proxy PDF bytes', { bytes: out.length, contentType: ct, contentDisposition: cd || '' });
      if (cd) res.set('Content-Disposition', cd);
      res.status(upstream.status).set('Content-Type', ct).send(out);
      return;
    }
    const text = await upstream.text();
    if (isJson) {
      try {
        res.set('Content-Type', contentType).json(JSON.parse(text));
      } catch (_) {
        res.set('Content-Type', contentType).send(text);
      }
    } else {
      res.set('Content-Type', contentType || 'text/plain').send(text);
    }
  } catch (e) {
    if (e.name === 'TimeoutError') {
      res.status(504).json({ success: false, error: 'Bayan proxy timed out' });
      return;
    }
    console.error('[Server] Bayan proxy fetch failed:', e?.message);
    res.status(502).json({ success: false, error: 'Upstream request failed: ' + (e?.message ?? 'unknown') });
  }
}

const server = app.listen(PORT, () => {
  log('Listening', `http://localhost:${PORT}`);
  log('Endpoints', `GET or POST ${PORT}/auth → cookie + accessToken`, 'GET /health → ok', `GET/POST ${PORT}/bayan/* → proxy to Bayan`);
  log('Auth timeout', `${AUTH_REQUEST_TIMEOUT_MS}ms`, 'Bayan base', BAYAN_BASE_URL);
});

function shutdown(signal) {
  log('Shutting down', signal);
  server.close((err) => {
    if (err) console.error('[Server] close error:', err?.message);
    process.exit(err ? 1 : 0);
  });
  setTimeout(() => process.exit(1), 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
