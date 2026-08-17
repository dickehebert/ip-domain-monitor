const dns = require('dns').promises;
const { createClient } = require('@supabase/supabase-js');

// Initialize Supabase Client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error("Missing SUPABASE_URL or SUPABASE_KEY environment variables.");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

const IP_BLACK_LISTS = [
  'zen.spamhaus.org',
  'b.barracudacentral.org',
  'bl.spamcop.net',
  'dnsbl.sorbs.net',
  'cbl.abuseat.org'
];

const DOMAIN_BLACK_LISTS = [
  'multi.surbl.org',
  'dbl.spamhaus.org'
];

async function checkTarget(type, value) {
  const lists = type === 'ip' ? IP_BLACK_LISTS : DOMAIN_BLACK_LISTS;
  const queryHost = type === 'ip' ? value.split('.').reverse().join('.') : value;
  const hits = [];

  for (const list of lists) {
    try {
      await dns.resolve4(`${queryHost}.${list}`);
      hits.push(list);
    } catch (e) {}
  }
  return hits;
}

async function runAudit() {
  console.log(`==================================================`);
  console.log(`[${new Date().toISOString()}] STARTING SUPABASE BLACKLIST AUDIT`);
  console.log(`==================================================\n`);

  // Fetch all targets registered across all API keys
  const { data: targets, error } = await supabase
    .from('monitored_targets')
    .select('*');

  if (error) {
    console.error('Database fetch failed:', error.message);
    return;
  }

  if (!targets || targets.length === 0) {
    console.log('No targets currently registered in database to audit.');
    return;
  }

  console.log(`Found ${targets.length} target(s) registered in database.\n`);

  for (const target of targets) {
    console.log(`Auditing [${target.type.toUpperCase()}] ${target.value}...`);
    
    const hits = await checkTarget(target.type, target.value);
    const newStatus = hits.length > 0 ? 'blacklisted' : 'clean';

    if (hits.length > 0) {
      console.log(`  ❌ BLACKLISTED! Listed on: ${hits.join(', ')}`);
    } else {
      console.log(`  ✅ CLEAN`);
    }

    // Update target status, blacklists hit, and timestamp back into Supabase
    const { error: updateError } = await supabase
      .from('monitored_targets')
      .update({
        status: newStatus,
        listings: hits,
        last_checked_at: new Date().toISOString()
      })
      .eq('id', target.id);

    if (updateError) {
      console.error(`  ⚠️ Failed to update database record: ${updateError.message}`);
    }
  }

  console.log(`\n==================================================`);
  console.log(`AUDIT COMPLETE`);
  console.log(`==================================================`);
}

runAudit();
