import {
  AngularNodeAppEngine,
  createNodeRequestHandler,
  isMainModule,
  writeResponseToNodeResponse,
} from '@angular/ssr/node';
import express from 'express';
import {join} from 'node:path';

const browserDistFolder = join(import.meta.dirname, '../browser');

const app = express();
const angularApp = new AngularNodeAppEngine();

app.use(express.json({limit: '25mb'}));

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'Arkhe Preflight v23 Provenance Engine',
    version: '23',
    releaseDate: '2026-10-11'
  });
});

app.get('/api/script/download', (req, res) => {
  const scriptPath = join(process.cwd(), 'arkhe_preflight_v23.py');
  res.download(scriptPath, 'arkhe_preflight_v23.py');
});

app.post('/api/solana-proxy', async (req, res) => {
  try {
    const { rpcUrl = 'https://api.devnet.solana.com', body } = req.body;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    const data = await response.json();
    res.json(data);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Solana proxy failed';
    res.status(502).json({ error: message, fallback: true });
  }
});

app.get('/api/solana/health', async (req, res) => {
  try {
    const target = (req.query['rpc'] as string) || 'https://api.devnet.solana.com';
    const start = Date.now();
    const resp = await fetch(target, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getHealth', params: [] }),
      signal: AbortSignal.timeout(5000)
    });
    const latency = Date.now() - start;
    const json = await resp.json();
    res.json({ ok: true, latencyMs: latency, result: json.result || 'ok' });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unreachable';
    res.status(200).json({ ok: false, error: msg });
  }
});


/**
 * Serve static files from /browser
 */
app.use(
  express.static(browserDistFolder, {
    maxAge: '1y',
    index: false,
    redirect: false,
  }),
);

/**
 * Handle all other requests by rendering the Angular application.
 */
app.use((req, res, next) => {
  angularApp
    .handle(req)
    .then((response) =>
      response ? writeResponseToNodeResponse(response, res) : next(),
    )
    .catch(next);
});

/**
 * Start the server if this module is the main entry point, or it is ran via PM2.
 * The server listens on the port defined by the `PORT` environment variable, or defaults to 4000.
 */
if (isMainModule(import.meta.url) || process.env['pm_id']) {
  const port = process.env['PORT'] || 4000;
  app.listen(port, (error) => {
    if (error) {
      throw error;
    }

    console.log(`Node Express server listening on http://localhost:${port}`);
  });
}

/**
 * Request handler used by the Angular CLI (for dev-server and during build) or Firebase Cloud Functions.
 */
export const reqHandler = createNodeRequestHandler(app);
