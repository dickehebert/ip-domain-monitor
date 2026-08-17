require('dotenv').config();
const dns = require('dns').promises;
const cron = require('node-cron');
const axios = require('axios');

const IPS = (process.env.TARGET_IPS || '').split(',').map(i => i.trim()).filter(Boolean);
const DOMAINS = (process.env.TARGET_DOMAINS || '').split(',').map(d => d.trim()).filter(Boolean);

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

const previousState = { ips: {}, domains: {} };

async function sendAlert(message) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) {
    console.log('[ALERT LOG]:\n' + message);
    return;
  }

  try {
    await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
      chat_id: chatId,
      text: message,
      parse_mode: 'Markdown'
    });
    console.log('Telegram alert dispatched.');
  } catch (err) {
    console.error('Telegram alert failed:', err.message);
  }
}

async function checkIp(ip) {
  const reversed = ip.split('.').reverse().join('.');
  const hits = [];
  for (const list of IP_BLACK_LISTS) {
    try {
      await dns.resolve4(`${reversed}.${list}`);
      hits.push(list);
    } catch (e) {}
  }
  return hits;
}

async function checkDomain(domain) {
  const hits = [];
  for (const list of DOMAIN_BLACK_LISTS) {
    try {
      await dns.resolve4(`${domain}.${list}`);
      hits.push(list);
    } catch (e) {}
  }
  return hits;
}

async function runAudit() {
  console.log(`[${new Date().toISOString()}] Starting Blacklist Audit...`);
  const alerts = [];

  for (const ip of IPS) {
    const current = await checkIp(ip);
    const prev = previousState.ips[ip] || [];
    const newlyListed = current.filter(x => !prev.includes(x));

    if (newlyListed.length > 0) {
      alerts.push(`🚨 *IP BLACKLIST ALERT*\n*IP:* \`${ip}\`\n*Listed on:* ${newlyListed.join(', ')}`);
    }
    previousState.ips[ip] = current;
  }

  for (const domain of DOMAINS) {
    const current = await checkDomain(domain);
    const prev = previousState.domains[domain] || [];
    const newlyListed = current.filter(x => !prev.includes(x));

    if (newlyListed.length > 0) {
      alerts.push(`🚨 *DOMAIN BLACKLIST ALERT*\n*Domain:* \`${domain}\`\n*Listed on:* ${newlyListed.join(', ')}`);
    }
    previousState.domains[domain] = current;
  }

  if (alerts.length > 0) {
    await sendAlert(alerts.join('\n\n'));
  } else {
    console.log('Audit complete. All targets clean.');
  }
}

// Runs every 6 hours
cron.schedule('0 */6 * * *', runAudit);

// Immediate execution on startup
runAudit();
