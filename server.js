
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Readable } = require("node:stream");

const app = express();

const PORT = process.env.PORT || 3000;

const SITE_ORIGIN =
  "https://admirable-madeleine-be5345.netlify.app";

const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || "")
  .split(",")
  .map(host => host.trim().toLowerCase())
  .filter(Boolean);

const MAX_SIZE = 500 * 1024 * 1024;

const MEDIA_TYPES = [
  "video/",
  "audio/",
  "application/octet-stream"
];

// Segurança básica
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

// Conexão com o site da Netlify
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin === SITE_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", SITE_ORIGIN);
    res.setHeader("Vary", "Origin");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, OPTIONS"
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type"
    );
  } else if (origin) {
    return res.status(403).json({
      error: "Origem não autorizada."
    });
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

// Validar endereço de download
function validarUrl(value) {
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

  const host = url.hostname.toLowerCase();

  if (!ALLOWED_HOSTS.includes(host)) {
    throw new Error(
      "Este domínio ainda não está autorizado."
    );
  }

  return url;
}

// Limpar nome do arquivo
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
    version: "1.1.0",
    message: "Servidor de downloads iniciado."
  });
});

// Verificar API
app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    downloads: true,
    version: "1.1.0"
  });
});

// API de download de arquivos diretos autorizados
app.get("/api/download", async (req, res) => {
  let remote;
  let response;

  try {
    remote = validarUrl(req.query.url);

    for (let attempt = 0; attempt < 4; attempt++) {
      response = await fetch(remote, {
        redirect: "manual",
        signal: AbortSignal.timeout(120000)
      });

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("location");

        if (!location) {
          throw new Error("Redirecionamento inválido.");
        }

        remote = validarUrl(
          new URL(location, remote).href
        );

        continue;
      }

      break;
    }

    if (!response || !response.ok) {
      throw new Error(
        "Não foi possível acessar o arquivo."
      );
    }

    const contentType = (
      response.headers.get("content-type") || ""
    ).split(";")[0].trim().toLowerCase();

    if (!MEDIA_TYPES.some(type =>
      contentType.startsWith(type)
    )) {
      throw new Error(
        "O endereço não forneceu um arquivo de mídia."
      );
    }

    const contentLength = Number(
      response.headers.get("content-length") || 0
    );

    if (contentLength > MAX_SIZE) {
      throw new Error(
        "O arquivo ultrapassa o limite de 500 MB."
      );
    }

    if (!response.body) {
      throw new Error("Arquivo indisponível.");
    }

    const pathName = decodeURIComponent(
      remote.pathname.split("/").pop() || "arquivo"
    );

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

    const stream = Readable.fromWeb(response.body);

    stream.on("error", () => {
      if (!res.headersSent) {
        res.status(502).json({
          error: "Erro ao transmitir o arquivo."
        });
      } else {
        res.destroy();
      }
    });

    stream.pipe(res);

  } catch (error) {
    if (response && response.body) {
      await response.body.cancel().catch(() => {});
    }

    if (!res.headersSent) {
      res.status(400).json({
        error: error.message || "Falha no download."
      });
    }
  }
});

// Iniciar servidor
app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Multi Download online na porta ${PORT}`
  );
});
