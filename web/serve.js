import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const basePort = Number(process.env.PORT || 3000);

function makeFetchHandler() {
  return async function fetch(req) {
    const url = new URL(req.url);
    // url.pathname starts with "/", and path.join would treat it as absolute.
    // Strip leading slashes so requests resolve under __dirname.
    const relPath = url.pathname.replace(/^\/+/, "");
    let filePath = path.join(__dirname, relPath);

    // Default to index.html
    if (url.pathname === "/") {
      filePath = path.join(__dirname, "index.html");
    }

    try {
      // Serve binary formats as bytes (not UTF-8 text), otherwise Arrow/Parquet decoding breaks.
      if (
        filePath.endsWith(".arrow") ||
        filePath.endsWith(".parquet") ||
        filePath.endsWith(".bin")
      ) {
        const buffer = await Bun.file(filePath).arrayBuffer();
        const contentType = getContentType(filePath);

        return new Response(buffer, {
          headers: {
            "Content-Type": contentType,
            "Access-Control-Allow-Origin": "*",
          },
        });
      }

      const file = await Bun.file(filePath).text();
      const contentType = getContentType(filePath);

      return new Response(file, {
        headers: {
          "Content-Type": contentType,
          "Access-Control-Allow-Origin": "*",
        },
      });
    } catch {
      // Fallback for any other file types (best-effort binary).
      try {
        const buffer = await Bun.file(filePath).arrayBuffer();
        const contentType = getContentType(filePath);

        return new Response(buffer, {
          headers: {
            "Content-Type": contentType,
            "Access-Control-Allow-Origin": "*",
          },
        });
      } catch {
        return new Response("Not Found", { status: 404 });
      }
    }
  };
}

function startServer() {
  for (let port = basePort; port < basePort + 200; port++) {
    try {
      const server = Bun.serve({ port, fetch: makeFetchHandler() });
      return { server, port };
    } catch (e) {
      if (e && (e.code === "EADDRINUSE" || String(e).includes("EADDRINUSE"))) {
        continue;
      }
      throw e;
    }
  }
  throw new Error(`No free port found in range ${basePort}-${basePort + 199}`);
}

// Keep a strong reference so the Bun server is not garbage-collected.
const { server, port } = startServer();

function getContentType(filePath) {
  if (filePath.endsWith(".html")) return "text/html";
  if (filePath.endsWith(".js")) return "application/javascript";
  if (filePath.endsWith(".css")) return "text/css";
  if (filePath.endsWith(".arrow")) return "application/octet-stream";
  if (filePath.endsWith(".parquet")) return "application/octet-stream";
  if (filePath.endsWith(".json")) return "application/json";
  if (filePath.endsWith(".csv")) return "text/csv";
  return "text/plain";
}

console.log(`
🚀 Cosmograph Server Running
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📍 http://localhost:${port}
📁 Serving from: ${__dirname}

Instructions:
1. Run 'bun convert' to generate Arrow files from CSVs
2. Open http://localhost:${port} in your browser
3. The app auto-loads ./nodes.arrow and ./edges.arrow
4. Use "Reload" if you regenerate the files

Press Ctrl+C to stop the server
`);

void server;
