
"use strict";

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const dns = require("node:dns").promises;
const net = require("node:net");
const https = require("node:https");
const path = require("node:path");
const { pipeline } = require("node:stream/promises");

const app = express();

app.set("trust proxy", 1);

app.disable("x-powered-by");

const PORT = Number(process.env.PORT) || 3000;

const SITE_ORIGIN =
  process.env.SITE_ORIGIN ||
  "https://multi-download-br.netlify.app";

const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || "")
  .split(",")
  .map((host) => host.trim().toLowerCase())
  .filter(Boolean);

const MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024;

const REQUEST_TIMEOUT = 30000;

app.use(helmet());

app.use(express.json({ limit: "20kb" }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", SITE_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Muitas solicitações. Tente novamente mais tarde."
  }
});

const downloadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Limite de downloads atingido. Tente novamente mais tarde."
  }
});

app.use(generalLimiter);

function isPrivateIPv4(ip) {
  if (net.isIP(ip) !== 4) {
    return true;
  }

  const parts = ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return true;
  }

  const [a, b, c] = parts;

  if (a === 0 || a === 10 || a === 127 || a >= 224) {
    return true;
  }

  if (a === 100 && b >= 64 && b <= 127) {
    return true;
  }

  if (a === 169 && b === 254) {
    return true;
  }

  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }

  if (a === 192 && b === 168) {
    return true;
  }

  if (a === 192 && b === 0 && c === 0) {
    return true;
  }

  if (a === 192 && b === 0 && c === 2) {
    return true;
  }

  if (a === 198 && (b === 18 || b === 19)) {
    return true;
  }

  if (a === 198 && b === 51 && c === 100) {
    return true;
  }

  if (a === 203 && b === 0 && c === 113) {
    return true;
  }

  return false;
}

function expandIPv6(ip) {
  let address = ip.toLowerCase().split("%")[0];

  if (address.includes(".")) {
    const lastColon = address.lastIndexOf(":");

    if (lastColon === -1) {
      return null;
    }

    const ipv4 = address.slice(lastColon + 1);

    if (net.isIP(ipv4) !== 4) {
      return null;
    }

    const octets = ipv4.split(".").map(Number);

    const first = ((octets[0] << 8) | octets[1])
      .toString(16);

    const second = ((octets[2] << 8) | octets[3])
      .toString(16);

    address = address.slice(0, lastColon) + ":" + first + ":" + second;
  }

  const halves = address.split("::");

  if (halves.length > 2) {
    return null;
  }

  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1]
    ? halves[1].split(":")
    : [];

  const missing = 8 - left.length - right.length;

  if (
    (halves.length === 1 && missing !== 0) ||
    (halves.length === 2 && missing < 1)
  ) {
    return null;
  }

  const groups = [
    ...left,
    ...Array(missing).fill("0"),
    ...right
  ];

  if (groups.length !== 8) {
    return null;
  }

  if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    return null;
  }

  return groups.map((group) => parseInt(group, 16));
}

function isPrivateIPv6(ip) {
  if (net.isIP(ip) !== 6) {
    return true;
  }

  const groups = expandIPv6(ip);

  if (!groups) {
    return true;
  }

  const allZero = groups.every((group) => group === 0);

  if (allZero) {
    return true;
  }

  const loopback =
    groups.slice(0, 7).every((group) => group === 0) &&
    groups[7] === 1;

  if (loopback) {
    return true;
  }

  // IPv4-mapped IPv6 addresses: ::ffff:a.b.c.d
  const ipv4Mapped =
    groups.slice(0, 5).every((group) => group === 0) &&
    groups[5] === 0xffff;

  if (ipv4Mapped) {
    const a = groups[6] >> 8;
    const b = groups[6] & 255;
    const c = groups[7] >> 8;
    const d = groups[7] & 255;

    return isPrivateIPv4(`${a}.${b}.${c}.${d}`);
  }

  // Unique local addresses: fc00::/7
  if ((groups[0] & 0xfe00) === 0xfc00) {
    return true;
  }

  // Link-local addresses: fe80::/10
  if ((groups[0] & 0xffc0) === 0xfe80) {
    return true;
  }

  // Multicast addresses: ff00::/8
  if ((groups[0] & 0xff00) === 0xff00) {
    return true;
  }

  // Documentation range: 2001:db8::/32
  if (
    groups[0] === 0x2001 &&
    groups[1] === 0x0db8
  ) {
    return true;
  }

  // IPv6 addresses outside global unicast space
  if ((groups[0] & 0xe000) !== 0x2000) {
    return true;
  }

  return false;
}

function isPublicIP(ip) {
  const version = net.isIP(ip);

  if (version === 4) {
    return !isPrivateIPv4(ip);
  }

  if (version === 6) {
    return !isPrivateIPv6(ip);
  }

  return false;
}

function normalizeHostname(hostname) {
  return hostname
    .toLowerCase()
    .replace(/\.$/, "");
}

function isAllowedHost(hostname) {
  const host = normalizeHostname(hostname);

  return ALLOWED_HOSTS.some((allowed) => {
    const normalized = normalizeHostname(allowed);

    return (
      host === normalized ||
      host.endsWith("." + normalized)
    );
  });
}

async function validateDestination(input) {
  let url;

  try {
    url = new URL(input);
  } catch {
    throw new Error("URL inválida.");
  }

  if (url.protocol !== "https:") {
    throw new Error("Somente URLs HTTPS são permitidas.");
  }

  if (url.username || url.password) {
    throw new Error("URLs com credenciais não são permitidas.");
  }

  if (url.port && url.port !== "443") {
    throw new Error("Somente a porta HTTPS 443 é permitida.");
  }

  const hostname = normalizeHostname(url.hostname);

  if (
    !hostname ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    throw new Error("Destino não permitido.");
  }

  if (net.isIP(hostname)) {
    if (!isPublicIP(hostname)) {
      throw new Error("Endereço IP privado ou reservado bloqueado.");
    }

    return {
      url,
      hostname,
      addresses: [{ address: hostname, family: net.isIP(hostname) }]
    };
  }

  if (!isAllowedHost(hostname)) {
    throw new Error("Este domínio não está autorizado.");
  }

  let addresses;

  try {
    addresses = await dns.lookup(hostname, {
      all: true,
      verbatim: true
    });
  } catch {
    throw new Error("Não foi possível verificar o domínio.");
  }

  if (!addresses.length) {
    throw new Error("O domínio não possui endereço válido.");
  }

  for (const entry of addresses) {
    if (!isPublicIP(entry.address)) {
      throw new Error("Domínio aponta para IP privado ou reservado.");
    }
  }

  return {
    url,
    hostname,
    addresses
  };
}

function safeFilename(value) {
  let filename = String(value || "download");

  try {
    filename = decodeURIComponent(filename);
  } catch {
    filename = "download";
  }

  filename = path.basename(filename);

  filename = filename
    .replace(/[^\w.\-() ]/g, "_")
    .replace(/^\.+/, "")
    .trim()
    .slice(0, 120);

  if (!filename || filename === "." || filename === "..") {
    filename = "download";
  }

  return filename;
}
app.get("/", (req, res) => {
  res.json({
    name: "Multi Download",
    status: "online",
    version: "4.0.0",
    message: "Servidor Multi Download iniciado."
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    name: "Multi Download",
    version: "4.0.0",
    downloads: true,
    directDownloads: ALLOWED_HOSTS.length > 0,
    security: {
      httpsOnly: true,
      privateIPv4Blocked: true,
      privateIPv6Blocked: true,
      redirectsBlocked: true,
      non443PortsBlocked: true
    },
    platforms: {
      youtube: false,
      tiktok: false,
      instagram: false,
      facebook: false,
      kwai: false,
      x: false
    }
  });
});

const PLATFORM_HOSTS = [
  {
    name: "YouTube",
    hosts: ["youtube.com", "youtu.be", "youtube-nocookie.com"]
  },
  {
    name: "TikTok",
    hosts: ["tiktok.com", "vm.tiktok.com", "vt.tiktok.com"]
  },
  {
    name: "Instagram",
    hosts: ["instagram.com"]
  },
  {
    name: "Facebook",
    hosts: ["facebook.com", "fb.watch"]
  },
  {
    name: "Kwai",
    hosts: ["kwai.com", "kwai-video.com"]
  },
  {
    name: "X",
    hosts: ["x.com", "twitter.com"]
  }
];

function identifyPlatform(hostname) {
  const host = normalizeHostname(hostname);

  for (const platform of PLATFORM_HOSTS) {
    if (
      platform.hosts.some(
        (domain) =>
          host === domain ||
          host.endsWith("." + domain)
      )
    ) {
      return platform.name;
    }
  }

  return null;
}

app.post("/api/inspect", async (req, res) => {
  try {
    const input = req.body?.url;

    if (typeof input !== "string" || !input.trim()) {
      return res.status(400).json({
        error: "Informe um link válido."
      });
    }

    let url;

    try {
      url = new URL(input.trim());
    } catch {
      return res.status(400).json({
        error: "O link informado não é válido."
      });
    }

    if (url.protocol !== "https:") {
      return res.status(400).json({
        error: "Somente links HTTPS são aceitos."
      });
    }

    if (url.username || url.password) {
      return res.status(400).json({
        error: "Link com credenciais não permitido."
      });
    }

    if (url.port && url.port !== "443") {
      return res.status(400).json({
        error: "Somente a porta 443 é permitida."
      });
    }

    const platform = identifyPlatform(url.hostname);

    if (platform) {
      return res.json({
        type: "platform",
        platform,
        recognized: true,
        downloadAvailable: false,
        message:
          "Plataforma reconhecida. A integração autorizada de download ainda não está configurada."
      });
    }

    const extension = path.extname(url.pathname).toLowerCase();

    const supportedExtensions = [
      ".mp4",
      ".mov",
      ".webm",
      ".mp3",
      ".wav",
      ".m4a",
      ".ogg",
      ".png",
      ".jpg",
      ".jpeg",
      ".webp",
      ".gif"
    ];

    if (supportedExtensions.includes(extension)) {
      return res.json({
        type: "direct-candidate",
        recognized: true,
        directCandidate: true,
        downloadAvailable: true,
        filename: safeFilename(
          path.basename(url.pathname)
        ),
        message:
          "Link direto identificado. A autorização do domínio será verificada no download."
      });
    }

    return res.json({
      type: "unknown",
      recognized: false,
      downloadAvailable: false,
      message:
        "Não foi possível identificar um arquivo compatível neste link."
    });
  } catch (error) {
    console.error("Erro em /api/inspect:", error.message);

    return res.status(500).json({
      error: "Erro interno ao analisar o link."
    });
  }
});

app.post("/api/download", downloadLimiter, async (req, res) => {
  let reader = null;
  let abortController = null;
  let completed = false;

  try {
    const input = req.body?.url;

    if (typeof input !== "string" || !input.trim()) {
      return res.status(400).json({
        error: "Informe o link do arquivo."
      });
    }

    const destination = await validateDestination(input.trim());

    abortController = new AbortController();

    const timeout = setTimeout(() => {
      abortController.abort(
        new Error("Tempo limite do download excedido.")
      );
    }, REQUEST_TIMEOUT);

    let response;

    try {
      const selectedAddress = destination.addresses[0];

      response = await fetch(destination.url, {
        method: "GET",
        redirect: "manual",
        signal: abortController.signal,
        headers: {
          "User-Agent": "MultiDownload/4.0"
        },
        dispatcher: undefined
      });
    } finally {
      clearTimeout(timeout);
    }

    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();

      return res.status(400).json({
        error: "Redirecionamentos não são permitidos por segurança."
      });
    }

    if (!response.ok) {
      await response.body?.cancel();

      return res.status(502).json({
        error: "O servidor de origem não disponibilizou o arquivo."
      });
    }

    const contentType = (
      response.headers.get("content-type") || ""
    ).toLowerCase();

    const allowedMimeTypes = [
      "video/",
      "audio/",
      "image/",
      "application/octet-stream"
    ];

    if (
      !allowedMimeTypes.some((type) =>
        contentType.startsWith(type)
      )
    ) {
      await response.body?.cancel();

      return res.status(415).json({
        error: "O conteúdo recebido não é um arquivo compatível."
      });
    }

    const contentLength = Number(
      response.headers.get("content-length") || 0
    );

    if (
      contentLength > 0 &&
      contentLength > MAX_DOWNLOAD_SIZE
    ) {
      await response.body?.cancel();

      return res.status(413).json({
        error: "O arquivo ultrapassa o limite permitido de 100 MB."
      });
    }

    if (!response.body) {
      return res.status(502).json({
        error: "O servidor de origem retornou um arquivo vazio."
      });
    }

    reader = response.body.getReader();

    const filename = safeFilename(
      path.basename(destination.url.pathname)
    );

    res.setHeader(
      "Content-Type",
      contentType || "application/octet-stream"
    );

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );

    if (contentLength > 0) {
      res.setHeader("Content-Length", contentLength);
    }

    res.setHeader("X-Content-Type-Options", "nosniff");

    req.on("aborted", () => {
      abortController.abort();
      reader?.cancel().catch(() => {});
    });

    res.on("close", () => {
      if (!completed) {
        abortController.abort();
        reader?.cancel().catch(() => {});
      }
    });

    let totalBytes = 0;

    while (true) {
      const { done, value } = await reader.read();

      if (done) {
        completed = true;
        break;
      }

      totalBytes += value.byteLength;

      if (totalBytes > MAX_DOWNLOAD_SIZE) {
        throw new Error("Arquivo ultrapassou o limite de 100 MB.");
      }

      if (res.destroyed) {
        throw new Error("Conexão encerrada pelo cliente.");
      }

      if (!res.write(Buffer.from(value))) {
        await new Promise((resolve, reject) => {
          res.once("drain", resolve);
          res.once("error", reject);
        });
      }
    }

    res.end();
  } catch (error) {
    console.error("Erro em /api/download:", error.message);

    if (reader) {
      try {
        await reader.cancel();
      } catch (cancelError) {
        console.error(
          "Erro ao cancelar stream:",
          cancelError.message
        );
      }
    }

    if (abortController) {
      abortController.abort();
    }

    if (!res.headersSent && !res.destroyed) {
      res.status(500).json({
        error: "Não foi possível concluir o download.",
        message: error.message
      });
    } else if (!res.destroyed) {
      res.destroy(error);
    }
  }
});

app.use((req, res) => {
  res.status(404).json({
    error: "Rota não encontrada."
  });
});

app.use((error, req, res, next) => {
  console.error("Erro geral:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "Erro interno do servidor."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Multi Download v4.0.0 online na porta ${PORT}`
  );
});
  
