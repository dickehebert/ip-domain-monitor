const dns = require('dns').promises;

// Hardcode your IPs and Domains here (separated by commas in the strings)
const IPS = ['192.0.2.1', '198.51.100.25']; // Replace with your SMTP server IPs
const DOMAINS = ['yourdomain.com'];         // Replace with your sending domains

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
  console.log(`==================================================`);
  console.log(`[${new Date().toISOString()}] STARTING BLACKLIST AUDIT`);
  console.log(`==================================================\n`);

  // Audit IPs
  for (const ip of IPS) {
    console.log(`Checking IP: ${ip}...`);
    const listings = await checkIp(ip);
    if (listings.length > 0) {
      console.log(`  ❌ BLACKLISTED! Listed on: ${listings.join(', ')}`);
    } else {
      console.log(`  ✅ CLEAN`);
    }
  }

  console.log(`\n--------------------------------------------------\n`);

  // Audit Domains
  for (const domain of DOMAINS) {
    console.log(`Checking Domain: ${domain}...`);
    const listings = await checkDomain(domain);
    if (listings.length > 0) {
      console.log(`  ❌ BLACKLISTED! Listed on: ${listings.join(', ')}`);
    } else {
      console.log(`  ✅ CLEAN`);
    }
  }

  console.log(`\n==================================================`);
  console.log(`AUDIT COMPLETE`);
  console.log(`==================================================`);
}

runAudit();
