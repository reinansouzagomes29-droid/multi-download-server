const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const dns = require("node:dns/promises");
const net = require("node:net");
const { Readable, Transform } = require("node:stream");
const { pipeline } = require("node:stream/promises");

const app = express();

const PORT = process.env.PORT || 3000;

const SITE_ORIGIN = "https://multi-download-br.netlify.app";

const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || "")
  .split(",")
  .map(host => host.trim().toLowerCase())
  .filter(Boolean);

const MAX_SIZE = 500 * 1024 * 1024;
const MAX_REDIRECTS = 4;

const MEDIA_TYPES = [
  "video/",
  "audio/",
  "application/octet-stream"
];

app.use(helmet());
app.use(express.json({ limit: "10kb" }));

// CORS
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && origin !== SITE_ORIGIN) {
    return res.status(403).json({
      error: "Origem não autorizada."
    });
  }

  if (origin === SITE_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", SITE_ORIGIN);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// Limite de requisições
app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 15,
  standardHeaders: "draft-8",
  legacyHeaders: false
}));

// Verificação básica de IP público
function ipPublico(ip) {
  if (net.isIP(ip) === 4) {
    const p = ip.split(".").map(Number);

    if (
      p[0] === 0 ||
      p[0] === 10 ||
      p[0] === 127 ||
      p[0] >= 224 ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 192 && p[1] === 0 && p[2] === 0) ||
      (p[0] === 192 && p[1] === 0 && p[2] === 2) ||
      (p[0] === 198 && (p[1] === 18 || p[1] === 19)) ||
      (p[0] === 198 && p[1] === 51 && p[2] === 100) ||
      (p[0] === 203 && p[1] === 0 && p[2] === 113)
    ) {
      return false;
    }

    return true;
  }

  if (net.isIP(ip) === 6) {
    const normalized = ip.toLowerCase();

    // Aceita apenas IPv6 global unicast
    return (
      (normalized.startsWith("2") || normalized.startsWith("3")) &&
      !normalized.startsWith("2001:db8:")
    );
  }

  return false;
}

// Validar endereço
async function validarUrl(value) {
  let url;

  try {
    url = new URL(value);
  } catch {
    throw new Error("Link inválido.");
  }

  if (url.protocol !== "https:") {
    throw new Error("Utilize um endereço HTTPS.");
  }

  if (url.username || url.password) {
    throw new Error("Endereço não permitido.");
  }

  if (url.port && url.port !== "443") {
    throw new Error("Porta não permitida.");
  }

  const host = url.hostname.toLowerCase();

  if (!ALLOWED_HOSTS.includes(host)) {
    throw new Error("Este domínio ainda não está autorizado.");
  }

  const addresses = await dns.lookup(host, {
    all: true,
    verbatim: true
  });

  if (!addresses.length || addresses.some(item => !ipPublico(item.address))) {
    throw new Error("Endereço de servidor não permitido.");
  }

  return url;
}

// Nome seguro do arquivo
function nomeSeguro(value) {
  return String(value || "arquivo")
    .replace(/[\r\n"]/g, "")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 120) || "arquivo";
}

// Página inicial
app.get("/", (req, res) => {
  res.json({
    name: "Multi Download",
    status: "online",
    version: "1.2.0",
    message: "Servidor de downloads iniciado."
  });
});

// Status da API
app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    downloads: true,
    version: "1.2.0"
  });
});

// Download de arquivos diretos autorizados
app.get("/api/download", async (req, res) => {
  let response;

  try {
    if (typeof req.query.url !== "string") {
      throw new Error("Informe um link para download.");
    }

    let remote = await validarUrl(req.query.url);

    for (let attempt = 0; attempt <= MAX_REDIRECTS; attempt++) {
      response = await fetch(remote, {
        redirect: "manual",
        signal: AbortSignal.timeout(120000)
      });

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("location");

        await response.body?.cancel().catch(() => {});

        if (!location || attempt === MAX_REDIRECTS) {
          throw new Error("Redirecionamento inválido ou excessivo.");
        }

        remote = await validarUrl(
          new URL(location, remote).href
        );

        continue;
      }

      break;
    }

    if (!response || !response.ok) {
      throw new Error("Não foi possível acessar o arquivo.");
    }

    const contentType = (
      response.headers.get("content-type") || ""
    ).split(";")[0].trim().toLowerCase();

    if (!MEDIA_TYPES.some(type => contentType.startsWith(type))) {
      throw new Error("O endereço não forneceu um arquivo de mídia.");
    }

    const contentLength = Number(
      response.headers.get("content-length") || 0
    );

    if (contentLength > MAX_SIZE) {
      throw new Error("O arquivo ultrapassa o limite de 500 MB.");
    }

    if (!response.body) {
      throw new Error("Arquivo indisponível.");
    }

    let pathName = "arquivo";

    try {
      pathName = decodeURIComponent(
        remote.pathname.split("/").pop() || "arquivo"
      );
    } catch {
      pathName = "arquivo";
    }

    const filename = nomeSeguro(pathName);

    res.setHeader("Content-Type", contentType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );
    res.setHeader("X-Content-Type-Options", "nosniff");

    if (contentLength > 0) {
      res.setHeader("Content-Length", contentLength);
    }

    let total = 0;

    const limiter = new Transform({
      transform(chunk, encoding, callback) {
        total += chunk.length;

        if (total > MAX_SIZE) {
          callback(new Error("Arquivo ultrapassa 500 MB."));
          return;
        }

        callback(null, chunk);
      }
    });

    await pipeline(
      Readable.fromWeb(response.body),
      limiter,
      res
    );

  } catch (error) {
    if (response?.body) {
      await response.body.cancel().catch(() => {});
    }

    if (!res.headersSent) {
      res.status(400).json({
        error: error.message || "Falha no download."
      });
    } else {
      res.destroy();
    }
  }
});

// Iniciar servidor
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Multi Download online na porta ${PORT}`);
});
       
