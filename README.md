# Bayan Get Auth API

Separate project that exposes an API to get **cookie** and **access token** for Bayan (logisti.sa). Use it from other services via HTTP.

## Setup

1. **Clone or copy** this folder.

2. **Install dependencies:**
   ```bash
   cd bayan-get-auth
   npm install
   ```

3. **Environment:** Copy `.env.example` to `.env` and set:
   - `BAYAN_IDENTITY_NUMBER` – Bayan identity number
   - `BAYAN_PASSWORD` – Bayan password
   - `BAYAN_OTP_SENDER` – OTP sender email (default: `NoReply@logisti.sa`)
   - Microsoft Graph (for OTP from email): `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `USER_EMAIL`

4. **Chrome/Chromium** must be installed (used by Puppeteer).

## Run

```bash
npm start
```

Server runs at `http://localhost:3000` (or `PORT` from `.env`).

## API

### `GET` or `POST` `/auth`

Performs login to Bayan, fetches OTP from email, then returns cookie and access token.

**Response (200):**
```json
{
  "success": true,
  "cookie": { "name1": "value1", "..." },
  "cookieHeader": "name1=value1; name2=value2; ...",
  "accessToken": "eyJ...",
  "headers": {
    "Cookie": "...",
    "User-Agent": "...",
    "Referer": "https://bayan.logisti.sa/",
    "Origin": "https://bayan.logisti.sa",
    "Authorization": "Bearer eyJ..."
  }
}
```

**Error (500):**
```json
{
  "success": false,
  "error": "Error message"
}
```

**Example:**
```bash
curl http://localhost:3000/auth
```

Use `cookieHeader` or `headers` in your downstream API calls to Bayan.
