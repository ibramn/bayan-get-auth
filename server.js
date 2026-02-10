import 'dotenv/config';
import express from 'express';
import { getAuth } from './authService.js';

const log = (...args) => console.log('[Server]', ...args);

const AUTH_REQUEST_TIMEOUT_MS = Number(process.env.AUTH_REQUEST_TIMEOUT_MS || 0) || 180000; // 3 min default

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

const server = app.listen(PORT, () => {
  log('Listening', `http://localhost:${PORT}`);
  log('Endpoints', `GET or POST ${PORT}/auth → cookie + accessToken`, 'GET /health → ok');
  log('Auth timeout', `${AUTH_REQUEST_TIMEOUT_MS}ms`);
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
