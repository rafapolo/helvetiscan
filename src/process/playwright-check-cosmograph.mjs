import { chromium } from 'playwright';

const url = process.argv[2] || process.env.URL || 'http://localhost:9000';
const timeoutMs = Number(process.env.TIMEOUT_MS || 120_000);
const explicitExecutablePath = process.env.PW_EXECUTABLE_PATH || process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
const headless = process.env.HEADLESS ? process.env.HEADLESS !== '0' : false;

function now() {
  return new Date().toISOString();
}

async function launchChromium() {
  try {
    return await chromium.launch({
      headless,
      args: headless
        ? ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist']
        : [],
    });
  } catch (e) {
    // Common on Apple Silicon when Node/Playwright expects x64 but only arm64 is present.
    const fallbackCandidates = [
      explicitExecutablePath,
      '/Users/polux/Library/Caches/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-mac-arm64/chrome-headless-shell',
      '/Users/polux/Library/Caches/ms-playwright/chromium_headless_shell-1181/chrome-headless-shell-mac-arm64/chrome-headless-shell',
    ].filter(Boolean);

    for (const p of fallbackCandidates) {
      try {
        console.log(`[${now()}] launch fallback executablePath=${p}`);
        return await chromium.launch({
          headless,
          executablePath: p,
          args: headless
            ? ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist']
            : [],
        });
      } catch {
        // keep trying
      }
    }
    throw e;
  }
}

const browser = await launchChromium();
const page = await browser.newPage();

let hadPageError = false;
let hadConsoleError = false;

page.on('pageerror', (err) => {
  hadPageError = true;
  console.log(`[${now()}] pageerror: ${err?.stack || err}`);
});

page.on('console', async (msg) => {
  const type = msg.type();
  const text = msg.text();
  if (type === 'error') hadConsoleError = true;

  // Try to print objects/arrays too (best effort)
  let args = '';
  try {
    const vals = await Promise.all(msg.args().map((a) => a.jsonValue().catch(() => undefined)));
    const extra = vals
      .filter((v) => v !== undefined)
      .map((v) => {
        if (typeof v === 'string') return v;
        try { return JSON.stringify(v); } catch { return String(v); }
      })
      .join(' ');
    if (extra && extra !== text) args = ` ${extra}`;
  } catch {}

  console.log(`[${now()}] console.${type}: ${text}${args}`);
});

console.log(`[${now()}] goto ${url}`);
await page.goto(url, { waitUntil: 'domcontentloaded' });

// Wait until app either succeeds or fails.
const started = Date.now();
while (Date.now() - started < timeoutMs) {
  const state = await page.evaluate(() => {
    const s = document.getElementById('status');
    return {
      statusText: s?.textContent || '',
      statusClass: s?.className || '',
      hasArrow: !!window.Arrow,
      cosmographType: typeof window.Cosmograph,
      cosmographKeys:
        window.Cosmograph && typeof window.Cosmograph === 'object' ? Object.keys(window.Cosmograph) : null,
      cosmographNsType: typeof window.cosmograph,
      cosmographNsKeys:
        window.cosmograph && typeof window.cosmograph === 'object' ? Object.keys(window.cosmograph) : null,
    };
  });

  if (state.statusClass === 'success') {
    console.log(`[${now()}] OK: status=success (${state.statusText})`);
    await browser.close();
    process.exit(0);
  }

  if (state.statusClass === 'error') {
    console.log(`[${now()}] FAIL: status=error (${state.statusText})`);
    console.log(`[${now()}] debug:`, JSON.stringify(state));
    await browser.close();
    process.exit(2);
  }

  // If Cosmograph seems missing, print one debug snapshot early.
  if (!state.hasArrow || (state.cosmographType !== 'function' && !state.cosmographKeys && !state.cosmographNsKeys)) {
    // no-op; console logs usually show enough
  }

  await page.waitForTimeout(500);
}

console.log(`[${now()}] TIMEOUT after ${timeoutMs}ms`);
await browser.close();
process.exit(hadPageError || hadConsoleError ? 3 : 4);
