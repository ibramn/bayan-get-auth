import 'dotenv/config';
import express from 'express';
import { getAuth } from './authService.js';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

/**
 * GET or POST /auth
 * Returns cookie and access token for Bayan (logisti.sa).
 */
app.all('/auth', async (req, res) => {
  try {
    const auth = await getAuth();
    res.json({
      success: true,
      cookie: auth.cookie,
      cookieHeader: auth.cookieHeader,
      accessToken: auth.accessToken,
      headers: auth.headers,
    });
  } catch (error) {
    console.error('Auth error:', error.message);
    res.status(500).json({
      success: false,
      error: error.message,
      code: error.code,
      debugScreenshot: error.debugScreenshot,
    });
  }
});

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Bayan Get Auth API running at http://localhost:${PORT}`);
  console.log(`  GET or POST http://localhost:${PORT}/auth → cookie + accessToken`);
});
