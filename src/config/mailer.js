const fs = require("fs");
const { Resend } = require("resend");
const dotenv = require("dotenv");

dotenv.config();

let resendClient = null;
let warnedMissingFrom = false;

const DEFAULT_RESEND_FROM = "Portal CONMEL <onboarding@resend.dev>";

function formatFromAddress(raw) {
  const v = String(raw).trim();
  if (!v) return null;
  if (v.includes("<") && v.includes(">")) return v;
  if (/^[^\s<>]+@[^\s<>]+$/.test(v)) {
    return `Portal CONMEL <${v}>`;
  }
  return v;
}

function resolveFrom(options) {
  if (options.from) {
    return options.from;
  }

  const fromEnv =
    process.env.RESEND_FROM_EMAIL ||
    process.env.RESEND_FROM ||
    "";

  const formatted = formatFromAddress(fromEnv);
  if (formatted) {
    return formatted;
  }

  if (!warnedMissingFrom) {
    warnedMissingFrom = true;
    console.warn(
      "[mailer] RESEND_FROM_EMAIL não definido; usando remetente de desenvolvimento Resend."
    );
  }
  return DEFAULT_RESEND_FROM;
}

function getResend() {
  const key = process.env.RESEND_API_KEY;
  if (!key || !String(key).trim()) {
    const err = new Error(
      "RESEND_API_KEY não configurada. Defina a chave re_... da Resend no ambiente."
    );
    err.code = "RESEND_NOT_CONFIGURED";
    throw err;
  }
  if (!resendClient) {
    resendClient = new Resend(String(key).trim());
  }
  return resendClient;
}

function normalizeRecipients(value) {
  if (value == null) return undefined;
  if (Array.isArray(value)) {
    return value
      .flatMap((v) =>
        typeof v === "string"
          ? v.split(",").map((s) => s.trim())
          : String(v)
      )
      .filter(Boolean);
  }
  if (typeof value === "string") {
    return value.includes(",")
      ? value.split(",").map((s) => s.trim()).filter(Boolean)
      : [value];
  }
  return [String(value)];
}

function mapAttachmentsForResend(attachments) {
  if (!attachments?.length) return undefined;
  return attachments.map((att) => {
    const filename = att.filename || "attachment";
    let content = att.content;
    if (att.path != null && content == null) {
      content = fs.readFileSync(att.path);
    }
    if (content == null) {
      throw new Error(`Anexo inválido (sem content ou path): ${filename}`);
    }
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const item = {
      filename,
      content: buf.toString("base64"),
    };
    if (att.contentType) item.contentType = att.contentType;
    return item;
  });
}

async function sendMail(options) {
  const resend = getResend();
  const to = normalizeRecipients(options.to);
  if (!to?.length) {
    throw new Error("Campo 'to' é obrigatório para envio de e-mail");
  }

  const payload = {
    from: resolveFrom(options),
    to: to.length === 1 ? to[0] : to,
    subject: options.subject,
  };

  if (options.html) payload.html = options.html;
  if (options.text) payload.text = options.text;
  if (options.replyTo) payload.replyTo = options.replyTo;

  const cc = normalizeRecipients(options.cc);
  if (cc?.length) payload.cc = cc.length === 1 ? cc[0] : cc;

  const bcc = normalizeRecipients(options.bcc);
  if (bcc?.length) payload.bcc = bcc.length === 1 ? bcc[0] : bcc;

  if (options.headers && Object.keys(options.headers).length) {
    payload.headers = options.headers;
  }

  const attachments = mapAttachmentsForResend(options.attachments);
  if (attachments) payload.attachments = attachments;

  const { data, error } = await resend.emails.send(payload);
  if (error) {
    const msg =
      typeof error.message === "string"
        ? error.message
        : JSON.stringify(error);
    const err = new Error(msg || "Falha ao enviar e-mail via Resend");
    err.resendError = error;
    throw err;
  }

  return { messageId: data?.id, ...data };
}

module.exports = { sendMail, sendEmail: sendMail };
