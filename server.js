// server.js
// Simple "Have I Been Pwned" style breach checker with AI-generated advice.
// Design principle: STATELESS. We never write the submitted email or the
// breach results to a database, file, or log. Nothing is stored, so there
// is nothing to "delete" later — privacy by default.

const express = require('express');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static(__dirname));
app.get('/', (req, res) => {
  res.sendFile('index.html', { root: __dirname });
});

// ---- Config (from .env, never hardcode keys) ----
const HIBP_API_KEY = process.env.HIBP_API_KEY;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const PORT = process.env.PORT || 3000;

if (!HIBP_API_KEY) {
  console.warn('WARNING: HIBP_API_KEY not set. /check-email will fail until you add it to .env');
}

// ---- Rate limiting ----
// Protects your paid HIBP key and your AI budget from abuse.
// 5 requests per minute per IP is generous for a demo/personal tool.
const checkLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please wait a minute and try again.' },
});

// ---- Basic email format validation ----
function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---- Route: check an email against HIBP ----
app.post('/check-email', checkLimiter, async (req, res) => {
  const { email } = req.body;

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please provide a valid email address.' });
  }

  try {
    const hibpRes = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      {
        headers: {
          'hibp-api-key': HIBP_API_KEY,
          'user-agent': 'simple-breach-checker-student-project',
        },
      }
    );

    // HIBP returns 404 when the email has NO breaches — that's a good outcome.
    if (hibpRes.status === 404) {
      return res.json({ breached: false, breaches: [] });
    }

    if (hibpRes.status === 401) {
      return res.status(500).json({ error: 'Server misconfiguration: invalid HIBP API key.' });
    }

    if (hibpRes.status === 429) {
      return res.status(429).json({ error: 'Rate limited by HIBP. Try again shortly.' });
    }

    if (!hibpRes.ok) {
      return res.status(502).json({ error: 'Breach lookup service unavailable.' });
    }

    const breaches = await hibpRes.json();

    // IMPORTANT: only send breach METADATA to the AI, never the email itself.
    const breachSummary = breaches.map((b) => ({
      name: b.Name,
      date: b.BreachDate,
      dataClasses: b.DataClasses, // e.g. ["Email addresses", "Passwords"]
    }));

    const advice = await getAiAdvice(breachSummary);

    return res.json({ breached: true, breaches: breachSummary, advice });
  } catch (err) {
    console.error('Error during breach check:', err.message);
    return res.status(500).json({ error: 'Something went wrong. Please try again later.' });
  }
});

// ---- AI advice generation (metadata-only, no PII sent) ----
async function getAiAdvice(breachSummary) {
  if (!ANTHROPIC_API_KEY) {
    return 'AI advice unavailable (no API key configured). Recommended: change passwords on affected sites, enable 2FA, and avoid reusing passwords.';
  }

  const dataClassesSeen = [...new Set(breachSummary.flatMap((b) => b.dataClasses))];
  const breachNames = breachSummary.map((b) => `${b.name} (${b.date})`).join(', ');

  const prompt = `A user's email appeared in these data breaches: ${breachNames}.
The exposed data types across all breaches were: ${dataClassesSeen.join(', ')}.
Do NOT ask for or reference the actual email address. Give 3-5 short, specific,
actionable security recommendations based on what was exposed (e.g. passwords,
security questions, phone numbers). Keep it under 120 words, plain text, no markdown.`;

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  const data = await response.json();
  const text = data?.content?.find((c) => c.type === 'text')?.text;
  return text || 'Change your passwords on the affected sites and enable two-factor authentication.';
}

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Breach checker running at http://localhost:${PORT}/`);
  });
}

module.exports = app;
