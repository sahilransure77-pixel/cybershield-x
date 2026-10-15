# CyberShield X

A starter web app for CyberShield X with a small, testable authentication flow. It includes a browser UI, an Express API, SQLite user storage, bcrypt password hashing, and short-lived JWTs held in an HttpOnly cookie.

> **Important:** This is a learning/demo starter, not a complete production-ready security product. Review it with a qualified developer before deploying or using real user accounts.

## Requirements

- Node.js 20 or newer
- npm (included with Node.js)

## Run on Windows 11

1. Download and install Node.js from the official website: https://nodejs.org/
2. Download or clone this repository.
3. Open Command Prompt or the VS Code terminal in the project folder.
4. Install packages:

   ```bash
   npm install
   ```

5. Copy `.env.example` to a new file named `.env`.
6. Replace `JWT_SECRET` in `.env` with a unique random secret of at least 32 characters. Keep `.env` private; it is ignored by Git.
7. Start the app:

   ```bash
   npm start
   ```

8. Open http://localhost:3000 in your browser and create a test account.

The SQLite database is created automatically at `data/cybershield.db` on first launch. It is local runtime data and is not committed to GitHub.

## Authentication flow

1. The browser sends the registration or login form to `POST /api/auth/register` or `POST /api/auth/login`.
2. Registration validates the input and stores a bcrypt hash (never the plain password). Login compares the submitted password with the stored hash.
3. On success, the server issues a JWT with a two-hour expiry and stores it in a `HttpOnly`, `SameSite=Strict` cookie. Browser JavaScript cannot read the cookie.
4. The browser automatically sends the cookie to `GET /api/auth/me`. Authentication middleware verifies the JWT signature, issuer, and expiry before returning the user's public profile.
5. `POST /api/auth/logout` clears the cookie.

## API routes

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/api/auth/register` | Create account and sign in |
| POST | `/api/auth/login` | Verify credentials and sign in |
| GET | `/api/auth/me` | Return current user; requires a valid session |
| POST | `/api/auth/logout` | Clear the browser session cookie |

Authentication routes are rate-limited. Helmet sets common security headers, SQL uses parameterized queries, and API request bodies have a size limit.

## Test checklist

- Register with a valid name, email, and password.
- Try registering the same email again; it should be rejected.
- Sign out, then sign in using the same credentials.
- Refresh the page while signed in; the session should be restored.
- Try opening `/api/auth/me` in a private/incognito window; it should return HTTP 401.
- Try a wrong password; login should fail without revealing whether the email exists.

## Before production

- Deploy only over HTTPS so secure cookies can be enabled with `NODE_ENV=production`.
- Use a strong unique secret from a secrets manager; never commit `.env`.
- Plan account recovery, email verification, monitoring, backups, dependency updates, CSRF review, and token/session revocation.
- Perform a security review and tests before storing real user data.

## Main files

- `server.js` — Express server, database, routes, password hashing, token verification
- `public/index.html` — sign-in and registration UI
- `public/app.js` — browser-to-API request flow
- `public/styles.css` — page styles
- `.env.example` — environment configuration template