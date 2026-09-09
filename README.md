# Email Breach Checker

A minimal web app that checks an email against Have I Been Pwned (HIBP) and
uses an AI model to generate protection advice. Built as a learning project
tying together HTTP, backend servers, third-party APIs, and privacy-by-design.

## Setup

1. Install dependencies:
   ```
   npm install
   ```
2. Copy `.env.example` to `.env` and add your keys:
   ```
   cp .env.example .env
   ```
   - `HIBP_API_KEY` — required. Get one at https://haveibeenpwned.com/API/Key
     (paid, a few dollars/month; rate-limited to roughly one request per few
     seconds).
   - `ANTHROPIC_API_KEY` — optional. Without it, you still get breach data,
     just with generic fallback advice instead of AI-generated advice.
3. Run it:
   ```
   npm start
   ```
4. Open http://localhost:3000

## Privacy design (read this before deploying anywhere public)

- **Nothing is stored.** The server never writes the submitted email or the
  breach results to a database, file, or log. This is intentional — a tool
  whose whole purpose is checking for data exposure shouldn't itself become
  a new pile of emails to leak. Because nothing is saved, there's no "delete
  my data" feature needed — there's no data to delete in the first place.
- **The AI never sees the email.** Only breach names, dates, and exposed data
  types (e.g. "Passwords", "Phone numbers") are sent to the AI — never the
  address itself.
- **Rate limiting** (5 requests/minute/IP) protects your paid HIBP key and
  your AI budget from abuse.
- **HTTPS required for real deployment.** This runs on plain HTTP locally for
  development only. If you deploy this anywhere public, put it behind HTTPS
  (e.g. a reverse proxy with Let's Encrypt, or a host that provides TLS by
  default) — you're handling email addresses, and HTTP would send them in
  plaintext.

## Next steps if you want to extend it

- Add CAPTCHA or another anti-abuse layer before the rate limiter — bots
  will find a public breach-checker eventually.
- Consider using HIBP's k-anonymity password-checking endpoint if you later
  want to check *passwords* too — it never sends the full password over the
  network, only a truncated hash prefix.
- If you ever do decide to store results (e.g. for a "check history"
  feature), that changes the risk profile a lot — you'd need encryption at
  rest, a real deletion flow, and a privacy policy. Stay stateless unless you
  have a clear reason not to.
