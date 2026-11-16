
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const dns = require("node:dns").promises;
const net = require("node:net");

const app = express();
const PORT = process.env.PORT || 10000;

const SITE_ORIGIN = "https://multi-download-br.netlify.app";
const MAX_FILE_SIZE = 500 * 1024 * 1024;

app.disable("x-powered-by");
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(express.json({ limit: "30kb" }));

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

const downloadLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    ok: false,
    error: "Muitas tentativas. Aguarde um minuto."
  }
});

const platformPatterns = [
  {
    name: "YouTube",
    patterns: [
      /(^|\.)youtube\.com$/i,
      /(^|\.)youtu\.be$/i,
      /(^|\.)youtube-nocookie\.com$/i
    ]
  },
  {
    name: "TikTok",
    patterns: [
      /(^|\.)tiktok\.com$/i,
      /(^|\.)tiktokv\.com$/i
    ]
  },
  {
    name: "Instagram",
    patterns: [
      /(^|\.)instagram\.com$/i
    ]
  },
  {
    name: "Facebook",
    patterns: [
      /(^|\.)facebook\.com$/i,
      /(^|\.)fb\.watch$/i,
      /(^|\.)fb\.com$/i
    ]
  },
  {
    name: "Kwai",
    patterns: [
      /(^|\.)kwai\.com$/i,
      /(^|\.)kuaishou\.com$/i
    ]
  },
  {
    name: "X",
    patterns: [
      /(^|\.)x\.com$/i,
      /(^|\.)twitter\.com$/i
    ]
  }
];

function identifyPlatform(url) {
  const hostname = url.hostname.toLowerCase();

  for (const platform of platformPatterns) {
    if (platform.patterns.some(pattern => pattern.test(hostname))) {
      return platform.name;
    }
  }

  return null;
}

function parseHttpUrl(value) {
  if (typeof value !== "string" || value.length > 4096) {
    throw new Error("Informe um endereço válido.");
  }

  let parsed;

  try {
    parsed = new URL(value.trim());
  } catch {
    throw new Error("O endereço informado é inválido.");
  }

  if (parsed.protocol !== "https:") {
    throw new Error("Por segurança, somente links HTTPS são aceitos.");
  }

  if (parsed.username || parsed.password) {
    throw new Error("Links com usuário ou senha não são aceitos.");
  }

  return parsed;
}

function isPublicIp(address) {
  const family = net.isIP(address);

  if (family === 4) {
    const parts = address.split(".").map(Number);
    const [a, b] = parts;

    if (
      a === 0 ||
      a === 10 ||
      a === 127 ||
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
      ip === "::" ||
      ip === "::1" ||
      ip.startsWith("fc") ||
      ip.startsWith("fd") ||
      ip.startsWith("fe8") ||
      ip.startsWith("fe9") ||
      ip.startsWith("fea") ||
      ip.startsWith("feb") ||
      ip.startsWith("::ffff:")
    ) {
      return false;
    }

    return true;
  }

  return false;
}

function getAllowedHosts() {
  return (process.env.ALLOWED_HOSTS || "")
    .split(",")
    .map(host => host.trim().toLowerCase())
    .filter(Boolean);
}

function hostIsAllowed(hostname) {
  const allowed = getAllowedHosts();

  return allowed.some(host =>
    hostname === host || hostname.endsWith("." + host)
  );
}

async function validateMediaUrl(url) {
  if (!hostIsAllowed(url.hostname.toLowerCase())) {
    throw new Error(
      "Este domínio não está autorizado para downloads neste servidor."
    );
  }

  const addresses = await dns.lookup(url.hostname, {
    all: true,
    verbatim: true
  });

  if (!addresses.length || addresses.some(item => !isPublicIp(item.address))) {
    throw new Error("O endereço do servidor não passou na validação de segurança.");
  }
}

function getFilename(url, contentType) {
  const pathname = decodeURIComponent(url.pathname);
  const lastPart = pathname.split("/").filter(Boolean).pop();

  if (lastPart && lastPart.includes(".")) {
    return lastPart.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120);
  }

  const extensions = {
    "video/mp4": "video.mp4",
    "video/webm": "video.webm",
    "audio/mpeg": "audio.mp3",
    "audio/mp3": "audio.mp3",
    "audio/mp4": "audio.m4a",
    "audio/wav": "audio.wav",
    "audio/ogg": "audio.ogg"
  };

  return extensions[contentType] || "arquivo-download";
}

app.get("/", (req, res) => {
  res.json({
    name: "Multi Download",
    status: "online",
    version: "2.0.0",
    message: "Servidor iniciado."
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    ok: true,
    online: true,
    downloads: true,
    version: "2.0.0",
    platformRecognition: true,
    imageTools: "browser",
    directMediaDownloads: getAllowedHosts().length > 0
  });
});

app.post("/api/inspect", (req, res) => {
  try {
    const url = parseHttpUrl(req.body.url);
    const platform = identifyPlatform(url);

    if (platform) {
      return res.json({
        ok: true,
        recognized: true,
        platform,
        type: "platform-page",
        downloadAvailable: false,
        message:
          "Plataforma reconhecida. O download depende de uma integração autorizada e da disponibilidade do conteúdo."
      });
    }

    return res.json({
      ok: true,
      recognized: true,
      platform: "Link externo",
      type: "direct-or-unknown",
      downloadAvailable: false,
      message:
        "Link reconhecido. Para confirmar se é um arquivo de mídia, use a opção de verificar arquivo."
    });
  } catch (error) {
    return res.status(400).json({
      ok: false,
      recognized: false,
      error: error.message
    });
  }
});

app.post("/api/download", downloadLimiter, async (req, res) => {
  let sourceUrl;

  try {
    sourceUrl = parseHttpUrl(req.body.url);

    const platform = identifyPlatform(sourceUrl);

    if (platform) {
      return res.status(400).json({
        ok: false,
        error:
          `${platform} foi reconhecido, mas este servidor ainda não possui uma integração autorizada para baixar esse conteúdo.`
      });
    }

    await validateMediaUrl(sourceUrl);

    const response = await fetch(sourceUrl, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(60000),
      headers: {
        "User-Agent": "MultiDownload/2.0"
      }
    });

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");

      if (!location) {
        throw new Error("O endereço redirecionou sem informar o destino.");
      }

      const redirectUrl = new URL(location, sourceUrl);

      if (redirectUrl.protocol !== "https:") {
        throw new Error("Redirecionamento inseguro bloqueado.");
      }

      await validateMediaUrl(redirectUrl);

      return res.status(400).json({
        ok: false,
        error:
          "Este arquivo usa redirecionamento. Por segurança, o servidor não seguirá esse endereço automaticamente."
      });
    }

    if (!response.ok) {
      throw new Error(`A fonte respondeu com o erro ${response.status}.`);
    }

    const contentType = (
      response.headers.get("content-type") || ""
    ).split(";")[0].trim().toLowerCase();

    const allowedTypes = [
      "video/",
      "audio/",
      "application/octet-stream"
    ];

    if (!allowedTypes.some(type =>
      type.endsWith("/") ? contentType.startsWith(type) : contentType === type
    )) {
      throw new Error("O endereço não parece ser um arquivo de vídeo ou áudio.");
    }

    const declaredLength = Number(response.headers.get("content-length") || 0);

    if (declaredLength > MAX_FILE_SIZE) {
      throw new Error("O arquivo ultrapassa o limite de 500 MB.");
    }

    if (!response.body) {
      throw new Error("A fonte não forneceu o arquivo.");
    }

    const filename = getFilename(sourceUrl, contentType);

    res.setHeader("Content-Type", contentType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );
    res.setHeader("X-Content-Type-Options", "nosniff");

    let total = 0;

    const reader = response.body.getReader();

    while (true) {
      const { done, value } = await reader.read();

      if (done) break;

      total += value.byteLength;

      if (total > MAX_FILE_SIZE) {
        await reader.cancel();
        if (!res.headersSent) {
          res.status(413).json({
            ok: false,
            error: "O arquivo ultrapassa o limite de 500 MB."
          });
        } else {
          res.destroy();
        }
        return;
      }

      if (!res.write(Buffer.from(value))) {
        await new Promise(resolve => res.once("drain", resolve));
      }
    }

    res.end();
  } catch (error) {
    console.error("Erro no download:", error.message);

    if (!res.headersSent) {
      res.status(400).json({
        ok: false,
        error: error.message || "Não foi possível processar o arquivo."
      });
    } else {
      res.destroy();
    }
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Multi Download 2.0.0 online na porta ${PORT}`);
});
