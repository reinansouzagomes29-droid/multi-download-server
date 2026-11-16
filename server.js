"use strict";

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const dns = require("node:dns").promises;
const net = require("node:net");

const app = express();

// Necessário para o express-rate-limit funcionar corretamente atrás de proxies (Render, Railway, etc.)
app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;
const SITE_ORIGIN = "https://multi-download-br.netlify.app";
const MAX_FILE_SIZE = 500 * 1024 * 1024;

app.disable("x-powered-by");

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(express.json({ limit: "20kb" }));

// --------------------------------------------------
// CORS
// --------------------------------------------------

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && origin !== SITE_ORIGIN) {
    return res.status(403).json({
      ok: false,
      error: "Origem não autorizada."
    });
  }

  res.setHeader("Access-Control-Allow-Origin", SITE_ORIGIN);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// --------------------------------------------------
// LIMITADOR DE REQUISIÇÕES
// --------------------------------------------------

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const downloadLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 8,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.use("/api", apiLimiter);

// --------------------------------------------------
// PLATAFORMAS RECONHECIDAS
// --------------------------------------------------

const PLATFORMS = [
  {
    name: "YouTube",
    hosts: ["youtube.com", "www.youtube.com", "m.youtube.com",
      "youtu.be", "music.youtube.com", "youtube-nocookie.com"]
  },
  {
    name: "TikTok",
    hosts: ["tiktok.com", "www.tiktok.com", "m.tiktok.com",
      "vm.tiktok.com", "vt.tiktok.com"]
  },
  {
    name: "Instagram",
    hosts: ["instagram.com", "www.instagram.com",
      "m.instagram.com"]
  },
  {
    name: "Facebook",
    hosts: ["facebook.com", "www.facebook.com", "m.facebook.com",
      "fb.watch", "fb.com"]
  },
  {
    name: "Kwai",
    hosts: ["kwai.com", "www.kwai.com", "m.kwai.com",
      "kuaishou.com", "www.kuaishou.com"]
  },
  {
    name: "X",
    hosts: ["x.com", "www.x.com", "twitter.com",
      "www.twitter.com", "mobile.twitter.com"]
  }
];

const MEDIA_EXTENSIONS = [
  ".mp4", ".m4v", ".webm", ".mov", ".mkv",
  ".mp3", ".m4a", ".aac", ".wav", ".ogg", ".flac"
];

const MIME_TYPES = [
  "video/mp4",
  "video/webm",
  "video/quicktime",
  "video/x-matroska",
  "audio/mpeg",
  "audio/mp4",
  "audio/aac",
  "audio/wav",
  "audio/x-wav",
  "audio/ogg",
  "audio/flac",
  "application/octet-stream"
];

// --------------------------------------------------
// UTILITÁRIOS
// --------------------------------------------------

function parseUrl(value) {
  if (typeof value !== "string" || value.length > 4096) {
    throw new Error("Informe um link válido.");
  }

  let url;

  try {
    url = new URL(value.trim());
  } catch {
    throw new Error("O link informado não é válido.");
  }

  if (url.protocol !== "https:") {
    throw new Error("Por segurança, utilize um link HTTPS.");
  }

  if (url.username || url.password) {
    throw new Error("Links com credenciais não são aceitos.");
  }

  if (url.port && url.port !== "443") {
    throw new Error("Apenas a porta HTTPS padrão (443) é permitida.");
  }

  return url;
}

function identifyPlatform(url) {
  const host = url.hostname.toLowerCase();

  for (const platform of PLATFORMS) {
    if (platform.hosts.includes(host)) {
      return platform.name;
    }
  }

  return null;
}

function looksLikeMediaFile(url) {
  const pathname = url.pathname.toLowerCase();
  return MEDIA_EXTENSIONS.some(extension =>
    pathname.endsWith(extension)
  );
}

function getAllowedHosts() {
  return (process.env.ALLOWED_HOSTS || "")
    .split(",")
    .map(host => host.trim().toLowerCase())
    .filter(Boolean);
}

function isHostAllowed(hostname) {
  const allowed = getAllowedHosts();

  return allowed.some(host =>
    hostname === host || hostname.endsWith("." + host)
  );
}

function isPublicIp(address) {
  const family = net.isIP(address);

  if (family === 4) {
    const [a, b] = address.split(".").map(Number);

    if (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    ) {
      return false;
    }

    return true;
  }

  if (family === 6) {
    const ip = address.toLowerCase();

    if (
      ip === "::" || ip === "::1" ||
      ip.startsWith("fc") || ip.startsWith("fd") ||
      ip.startsWith("fe8") || ip.startsWith("fe9") ||
      ip.startsWith("fea") || ip.startsWith("feb") ||
      ip.startsWith("::ffff:") ||
      ip.startsWith("2002:") ||
      ip.startsWith("64:ff9b:")
    ) {
      return false;
    }

    return true;
  }

  return false;
}

async function validateDirectHost(url) {
  const hostname = url.hostname.toLowerCase();

  if (net.isIP(hostname) !== 0) {
    throw new Error("Endereços IP diretos não são permitidos.");
  }

  if (!isHostAllowed(hostname)) {
    throw new Error(
      "Este domínio ainda não foi autorizado para downloads."
    );
  }

  const addresses = await dns.lookup(hostname, {
    all: true,
    verbatim: true
  });

  if (
    !addresses.length ||
    addresses.some(item => !isPublicIp(item.address))
  ) {
    throw new Error("O endereço de destino não passou na validação.");
  }
}

function safeFilename(url, contentType) {
  try {
    const lastPart = decodeURIComponent(url.pathname)
      .split("/")
      .filter(Boolean)
      .pop();

    if (lastPart && /\.[a-z0-9]{2,5}$/i.test(lastPart)) {
      return lastPart.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120);
    }
  } catch {
    // Ignora falha de decodeURIComponent e usa fallback
  }

  const fallback = {
    "video/mp4": "video.mp4",
    "video/webm": "video.webm",
    "video/quicktime": "video.mov",
    "video/x-matroska": "video.mkv",
    "audio/mpeg": "audio.mp3",
    "audio/mp4": "audio.m4a",
    "audio/aac": "audio.aac",
    "audio/wav": "audio.wav",
    "audio/x-wav": "audio.wav",
    "audio/ogg": "audio.ogg",
    "audio/flac": "audio.flac"
  };

  return fallback[contentType] || "arquivo-midia";
}

// --------------------------------------------------
// ADAPTADORES DE PLATAFORMA
// --------------------------------------------------

const platformAdapters = {
  "YouTube": null,
  "TikTok": null,
  "Instagram": null,
  "Facebook": null,
  "Kwai": null,
  "X": null
};

function getPlatformStatus(platform) {
  const adapter = platformAdapters[platform];

  return {
    recognized: true,
    platform,
    integrationConfigured: Boolean(adapter),
    downloadAvailable: false,
    message: adapter
      ? "Integração configurada. A disponibilidade será verificada pela fonte."
      : "Plataforma reconhecida. A integração de download ainda não está configurada."
  };
}

// --------------------------------------------------
// ROTAS PRINCIPAIS
// --------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    name: "Multi Download",
    status: "online",
    version: "3.0.0",
    message: "Servidor Multi Download iniciado."
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    ok: true,
    online: true,
    version: "3.0.0",
    platformRecognition: true,
    directDownloads: getAllowedHosts().length > 0,
    imageConversion: "browser",
    platforms: PLATFORMS.map(platform => ({
      name: platform.name,
      recognized: true,
      integrationConfigured: Boolean(platformAdapters[platform.name])
    }))
  });
});

// --------------------------------------------------
// IDENTIFICAR LINK
// --------------------------------------------------

app.post("/api/inspect", (req, res) => {
  try {
    const url = parseUrl(req.body?.url);
    const platform = identifyPlatform(url);

    if (platform) {
      return res.json({
        ok: true,
        type: "platform",
        ...getPlatformStatus(platform)
      });
    }

    const directCandidate = looksLikeMediaFile(url);
    const hostAllowed = isHostAllowed(url.hostname.toLowerCase());

    return res.json({
      ok: true,
      type: directCandidate ? "direct-candidate" : "unknown",
      recognized: true,
      platform: "Link externo",
      directCandidate,
      downloadAvailable: directCandidate && hostAllowed,
      message: directCandidate
        ? hostAllowed
          ? "O endereço parece apontar para um arquivo de mídia autorizado."
          : "O endereço parece ser um arquivo de mídia, mas o domínio não está na lista de permitidos."
        : "O endereço foi reconhecido, mas não parece ser um link direto de vídeo ou áudio."
    });

  } catch (error) {
    return res.status(400).json({
      ok: false,
      recognized: false,
      error: error.message
    });
  }
});

// --------------------------------------------------
// DOWNLOAD DIRETO AUTORIZADO
// --------------------------------------------------

app.post("/api/download", downloadLimiter, async (req, res) => {
  let source;
  let reader;

  try {
    source = parseUrl(req.body?.url);

    const platform = identifyPlatform(source);

    if (platform) {
      return res.status(400).json({
        ok: false,
        error:
          `${platform} foi reconhecido, mas não há um adaptador de download configurado para esta plataforma.`
      });
    }

  
