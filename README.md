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

### Running headless on Amazon Linux

To run on **Amazon Linux 2** or **Amazon Linux 2023** (headless, no display):

1. **Install Chromium and dependencies** (required for Puppeteer):

   **Amazon Linux 2023:**
   ```bash
   sudo dnf install -y chromium
   ```
   If the binary is not in `PATH`, set in `.env`:
   ```bash
   PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
   ```
   or the path reported by `which chromium` / `dnf list installed chromium`.

   **Amazon Linux 2:**
   ```bash
   sudo amazon-linux-extras install -y epel
   sudo yum install -y chromium
   ```
   Or install [Google Chrome for Linux](https://www.google.com/chrome/browser/desktop/index.html) and set `PUPPETEER_EXECUTABLE_PATH` to the chrome binary.

2. **Install libraries** Chromium needs on minimal installs (fonts + libs):
   ```bash
   # AL2023
   sudo dnf install -y \
     nss atk at-spi2-atk cups-libs gtk3 libXcomposite libXdamage libXrandr \
     libgbm pango alsa-lib
   # AL2
   sudo yum install -y \
     nss atk at-spi2-atk cups-libs gtk3 libXcomposite libXdamage libXrandr \
     libgbm pango alsa-lib
   ```

3. **Run headless** (default): do not set `HEADLESS=false`. The app defaults to headless and uses flags like `--no-sandbox` and `--disable-dev-shm-usage` on Linux.

4. **Optional:** Run the app under a process manager (systemd, PM2, etc.) and set `PORT` and other env vars there.

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
