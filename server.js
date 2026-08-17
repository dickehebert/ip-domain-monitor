require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Middleware: Authenticate user requests via x-api-key header
async function authenticateKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing x-api-key header' });

  const { data, error } = await supabase
    .from('api_keys')
    .select('id')
    .eq('api_key', apiKey)
    .eq('is_active', true)
    .single();

  if (error || !data) return res.status(403).json({ error: 'Invalid or inactive API key' });

  req.keyId = data.id;
  next();
}

// Endpoint: Fetch monitored targets
app.get('/v1/targets', authenticateKey, async (req, res) => {
  const { data, error } = await supabase
    .from('monitored_targets')
    .select('type, value, status, listings, last_checked_at')
    .eq('api_key_id', req.keyId);

  if (error) return res.status(500).json({ error: error.message });
  return res.json({ targets: data });
});

// Endpoint: Users submit IP or Domain for monitoring
app.post('/v1/targets', authenticateKey, async (req, res) => {
  const { type, value } = req.body;

  if (!['ip', 'domain'].includes(type) || !value) {
    return res.status(400).json({ error: 'Invalid payload. Expects { "type": "ip"|"domain", "value": "..." }' });
  }

  const { error } = await supabase
    .from('monitored_targets')
    .upsert({ api_key_id: req.keyId, type, value, status: 'pending' }, { onConflict: 'api_key_id,type,value' });

  if (error) return res.status(500).json({ error: error.message });

  // Instantly trigger GitHub Actions workflow scan
  if (process.env.GITHUB_TOKEN && process.env.GITHUB_REPO) {
    fetch(`https://api.github.com/repos/${process.env.GITHUB_REPO}/actions/workflows/blacklist-check.yml/dispatches`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Render-API-Gateway'
      },
      body: JSON.stringify({ ref: 'main' })
    }).catch(err => console.error('Failed to trigger GitHub Action dispatch:', err));
  }

  return res.status(201).json({ message: `${type.toUpperCase()} registered. Instant scan queued successfully.` });
});

app.listen(process.env.PORT || 3000, () => console.log('API Server running'));

// Endpoint: Remove a target from monitoring
app.delete('/v1/targets', authenticateKey, async (req, res) => {
  const { type, value } = req.body;

  if (!type || !value) {
    return res.status(400).json({ error: 'Missing type or value in request body.' });
  }

  const { error } = await supabase
    .from('monitored_targets')
    .delete()
    .eq('api_key_id', req.keyId)
    .eq('type', type)
    .eq('value', value);

  if (error) return res.status(500).json({ error: error.message });
  return res.json({ message: 'Target removed successfully.' });
});
