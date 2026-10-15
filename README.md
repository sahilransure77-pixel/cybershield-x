# CyberShield X

CyberShield X is a student cybersecurity learning web app. It includes account registration and login, a security dashboard, a heuristic URL warning checker, a browser-only password strength guide, saved suspicious-link reports, and security awareness tips.

> **Important:** This is an educational demo, not a commercial threat-intelligence product. URL checks use simple patterns, do not visit the submitted website, and cannot determine that a link is safe. Reports are stored in this app's SQLite database and are not sent to a real response team.

## Features

- **Authentication:** Express API, SQLite user records, bcrypt password hashing, short-lived JWT in an HttpOnly/SameSite cookie, rate-limited login and registration.
- **URL warning checker:** Looks for basic URL indicators such as plain HTTP, URL shorteners, punycode, long hostnames, and some commonly abused TLDs. It does not fetch URLs or check a live reputation feed.
- **Password strength guide:** Runs in the browser; the password entered in this tool is not sent to the server. The estimate is educational and is not a crack-time guarantee.
- **Suspicious-link reports:** Save a URL and reason to the signed-in user's own report list.
- **Awareness guide:** Practical tips for spotting suspicious messages, protecting accounts, and keeping devices updated.
- **Responsive interface:** Desktop and mobile layouts.
- **Automated tests and CI:** Node's built-in test runner and GitHub Actions syntax/test checks.

## Requirements

- Node.js 20 or newer
- npm (included with Node.js)

## Run on Windows 11

1. Install Node.js from the official website: https://nodejs.org/
2. Download the repository ZIP from GitHub and extract it, or clone the repository.
3. Open Command Prompt or the VS Code terminal in the extracted `cybershield-x` folder.
4. Install dependencies:

   ```bash
   npm install
   ```

5. Copy `.env.example` to a new file named `.env`.
6. Open `.env` and replace the sample `JWT_SECRET` with a unique random secret at least 32 characters long. Never share or commit this file.
7. Run syntax checks and tests:

   ```bash
   npm run check
   npm test
   ```

8. Start the app:

   ```bash
   npm start
   ```

9. Open http://localhost:3000, create a test account, then explore the dashboard tools.

The SQLite database is created automatically in `data/cybershield.db`. It contains local runtime data and should not be committed to GitHub.

## API routes

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/api/auth/register` | Create an account and sign in |
| POST | `/api/auth/login` | Sign in |
| GET | `/api/auth/me` | Get the signed-in user's profile |
| POST | `/api/auth/logout` | Clear the session cookie |
| POST | `/api/security/check-url` | Run the URL heuristic check (authentication required) |
| POST | `/api/reports` | Save a suspicious-link report (authentication required) |
| GET | `/api/reports` | List the signed-in user's latest 20 reports |

## Security notes

- Passwords are hashed with bcrypt and are never stored in plain text.
- Database queries use parameters.
- Helmet adds common HTTP security headers; JSON bodies are size-limited.
- Authentication and tool endpoints are rate-limited.
- The password strength tool runs locally in the browser and does not send its input to the API.
- URL analysis does not fetch user-submitted URLs, reducing SSRF risk.
- The session cookie is HttpOnly and SameSite Strict. Production deployments must use HTTPS with `NODE_ENV=production`.
- This demo does not include email verification, account recovery, CSRF tokens, MFA, external threat intelligence, alert delivery, or a full security audit. Do not deploy publicly or use real sensitive accounts without a proper review.

## Test checklist

- Register using a valid name, email and password.
- Try registering the same email twice; the second attempt should be rejected.
- Sign out and sign back in.
- Refresh while signed in; the session should be restored.
- Check a sample URL and review the heuristic findings.
- Use the password guide and verify its input is not sent to the API.
- Save a suspicious-link report and confirm it appears in your report list.
- Open `/api/auth/me` in a private window; it should return HTTP 401.

## Project structure

- `server.js` — Express API, SQLite schema, authentication and report routes
- `security.js` — URL normalization and heuristic analysis
- `public/index.html` — login, dashboard and feature views
- `public/app.js` — UI behavior and API calls
- `public/styles.css` — responsive dashboard theme
- `tests/security.test.js` — automated URL analysis tests
- `.github/workflows/ci.yml` — GitHub Actions checks
- `.env.example` — environment configuration template
