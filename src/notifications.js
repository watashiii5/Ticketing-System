const nodemailer = require("nodemailer");

let transport = null;

function getTransport() {
  if (!transport && process.env.SMTP_HOST) {
    transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: false,
      auth: process.env.SMTP_USER
        ? {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
          }
        : undefined,
    });
  }
  return transport;
}

function sendTicketNotification({ subject, text, to }) {
  const finalTo = to || process.env.NOTIFY_TO;
  if (!process.env.SMTP_HOST || !finalTo) {
    console.log("[notify]", subject, text.replace(/\n/g, " "));
    return;
  }

  const from = process.env.NOTIFY_FROM || "service-desk@acme.test";

  getTransport()
    ?.sendMail({ from, to: finalTo, subject, text })
    .catch((err) => console.error("Notification error", err));
}

module.exports = { sendTicketNotification };
