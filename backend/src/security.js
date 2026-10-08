const crypto = require('crypto');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');
const BLOCKED = new Set(['unspecified','broadcast','multicast','linkLocal','loopback','private','reserved','carrierGradeNat','uniqueLocal','ipv4Mapped']);
const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');
function newToken() { return `ff_${crypto.randomBytes(24).toString('base64url')}`; }
async function assertSafeUrl(value) {
  let url; try { url = new URL(value); } catch { throw new Error('Invalid URL'); }
  if (!['http:','https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS URLs are allowed');
  const addresses = await dns.lookup(url.hostname, { all: true, verbatim: true });
  addresses.forEach(({ address }) => { if (BLOCKED.has(ipaddr.parse(address).range())) throw new Error('Private network URLs are not allowed'); });
  return url.toString();
}
function escapeCsv(value) {
  let text = value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}
function signWebhook(secret, payload) { return `sha256=${crypto.createHmac('sha256', secret).update(payload).digest('hex')}`; }
module.exports = { assertSafeUrl, escapeCsv, newToken, sha256, signWebhook };
