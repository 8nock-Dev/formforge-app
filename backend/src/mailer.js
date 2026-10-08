const nodemailer = require('nodemailer');

let cachedTransport = null;
function transport() {
  if (!process.env.SMTP_HOST) return null;
  if (cachedTransport) return cachedTransport;
  cachedTransport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  return cachedTransport;
}

async function sendEmail({ to, subject, html }) {
  const mailer = transport();
  if (!mailer) {
    console.log(`[Email disabled] ${subject}`);
    return null;
  }
  return mailer.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to, subject, html });
}

module.exports = { sendEmail };
