require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');

const app = express();
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

// Endpoint: Users submit IP or Domain for monitoring
app.post('/v1/targets', authenticateKey, async (req, res) => {
  const { type, value } = req.body;

  if (!['ip', 'domain'].includes(type) || !value) {
    return res.status(400).json({ error: 'Invalid payload. Expects { "type": "ip"|"domain", "value": "..." }' });
  }

  const { data, error } = await supabase
    .from('monitored_targets')
    .upsert({ api_key_id: req.keyId, type, value, status: 'pending' }, { onConflict: 'api_key_id,type,value' });

  if (error) return res.status(500).json({ error: error.message });
  return res.status(201).json({ message: `${type.toUpperCase()} registered for monitoring successfully.` });
});

app.listen(process.env.PORT || 3000, () => console.log('API Server running'));
