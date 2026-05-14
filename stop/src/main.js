const { exec: execCb, spawn } = require("node:child_process");
const { promisify } = require("node:util");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");

const exec = promisify(execCb);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function appendOutput(key, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    const delimiter = `ghadelimiter_${crypto.randomUUID()}`;
    await fs.appendFile(outputFile, `${key}<<${delimiter}\n${value}\n${delimiter}\n`);
  }
}

async function saveState(key, value) {
  const stateFile = process.env.GITHUB_STATE;
  if (stateFile) {
    const delimiter = `ghadelimiter_${crypto.randomUUID()}`;
    await fs.appendFile(stateFile, `${key}<<${delimiter}\n${value}\n${delimiter}\n`);
  }
}

function getInput(name) {
  const envName = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  return (process.env[envName] || "").trim();
}

async function run(cmd, opts = {}) {
  console.log(`> ${cmd}`);
  try {
    await exec(cmd, opts);
  } catch (e) {
    if (!opts.ignoreError) throw e;
  }
}

async function exists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

function csv(value) {
  return (value || "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

function globToRegExp(pattern) {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

function matchGlobList(value, patterns) {
  if (!patterns.length) {
    return false;
  }
  return patterns.some((pattern) => globToRegExp(pattern).test(value));
}

function getHeader(headers, name) {
  if (!Array.isArray(headers)) {
    return "";
  }
  const lowerName = name.toLowerCase();
  const item = headers.find((h) => (h.name || "").toLowerCase() === lowerName);
  return (item?.value || "").trim();
}

async function filterHarInPlace(harPath) {
  if (!(await exists(harPath))) {
    return;
  }

  const allowDomains = csv(process.env.PCAP_FILTER_DOMAINS);
  const denyDomains = csv(process.env.PCAP_FILTER_EXCLUDE_DOMAINS);
  const referers = csv(process.env.PCAP_FILTER_REFERERS);
  const contentTypes = csv(process.env.PCAP_FILTER_CONTENT_TYPES).map((v) =>
    v.toLowerCase()
  );
  const maxBodySize = Number.parseInt(process.env.PCAP_FILTER_MAX_BODY_SIZE || "0", 10) || 0;

  if (
    !allowDomains.length &&
    !denyDomains.length &&
    !referers.length &&
    !contentTypes.length &&
    maxBodySize <= 0
  ) {
    return;
  }

  const raw = await fs.readFile(harPath, "utf8");
  const har = JSON.parse(raw);
  const entries = Array.isArray(har?.log?.entries) ? har.log.entries : [];

  const filtered = entries.filter((entry) => {
    const request = entry?.request || {};
    const response = entry?.response || {};

    let host = "";
    try {
      host = new URL(request.url || "").hostname || "";
    } catch {
      host = "";
    }

    if (allowDomains.length && !matchGlobList(host, allowDomains)) {
      return false;
    }
    if (denyDomains.length && matchGlobList(host, denyDomains)) {
      return false;
    }

    const referer = getHeader(request.headers, "referer");
    if (referers.length && !matchGlobList(referer, referers)) {
      return false;
    }

    const contentType = (response?.content?.mimeType || "").toLowerCase();
    if (contentTypes.length && !contentTypes.some((ct) => contentType.startsWith(ct))) {
      return false;
    }

    const bodySize = Number(response?.bodySize ?? response?.content?.size ?? 0);
    if (maxBodySize > 0 && bodySize > maxBodySize) {
      return false;
    }

    return true;
  });

  har.log.entries = filtered;
  await fs.writeFile(harPath, JSON.stringify(har));
  console.log(`Filtered Fluxzy HAR entries: ${entries.length} -> ${filtered.length}`);
}

async function killProcess(pid, { sudo = false } = {}) {
  const prefix = sudo ? "sudo " : "";
  await run(`${prefix}kill ${pid} 2>/dev/null || true`, {
    ignoreError: true,
    shell: "/bin/bash",
  });
  await sleep(2000);
  await run(`${prefix}kill -9 ${pid} 2>/dev/null || true`, {
    ignoreError: true,
    shell: "/bin/bash",
  });
}

async function main() {
  const captureDir =
    getInput("capture-dir") ||
    process.env.PCAP_CAPTURE_DIR ||
    "";

  if (!captureDir) {
    console.error(
      "::error::No capture directory. Did you run the start action first?"
    );
    process.exit(1);
  }

  console.log(`Capture directory: ${captureDir}`);
  const proxyTool = (process.env.PCAP_PROXY_TOOL || "mitmproxy").toLowerCase();
  console.log(`Proxy tool: ${proxyTool}`);

  // ── Stop proxy process ──────────────────────────────────────────
  const pidFile =
    proxyTool === "fluxzy"
      ? path.join(captureDir, "fluxzy.pid")
      : path.join(captureDir, "mitmdump.pid");
  const logFile =
    proxyTool === "fluxzy"
      ? path.join(captureDir, "fluxzy-stdout.log")
      : path.join(captureDir, "mitmdump-stdout.log");

  if (await exists(pidFile)) {
    const pid = (await fs.readFile(pidFile, "utf8")).trim();
    console.log(`Stopping ${proxyTool} (PID ${pid})...`);
    if (os.platform() === "win32") {
      await run(`taskkill /PID ${pid} /F`, { ignoreError: true });
    } else {
      await killProcess(pid);
    }
    await fs.unlink(pidFile);
    console.log(`${proxyTool} stopped`);

    if (await exists(logFile)) {
      const log = (await fs.readFile(logFile, "utf8")).trim();
      if (log) {
        console.log(`::group::${proxyTool} log`);
        console.log(log);
        console.log("::endgroup::");
      }
    }
  } else {
    console.log(`::warning::${proxyTool} PID file not found`);
  }

  // ── Stop tcpdump / netsh ────────────────────────────────────────
  if (os.platform() !== "win32") {
    const tcpdumpPidFile = path.join(captureDir, "tcpdump.pid");
    if (await exists(tcpdumpPidFile)) {
      const pid = (await fs.readFile(tcpdumpPidFile, "utf8")).trim();
      console.log(`Stopping tcpdump (PID ${pid})...`);
      await killProcess(pid, { sudo: true });
      await fs.unlink(tcpdumpPidFile);
      console.log("tcpdump stopped");
    }
  } else {
    console.log("Stopping netsh trace...");
    await run("netsh trace stop", { ignoreError: true });

    const etlFile = path.join(captureDir, "raw-capture.etl");
    const pcapFile = path.join(captureDir, "raw-capture.pcap");
    if (await exists(etlFile)) {
      try {
        await run(`etl2pcapng "${etlFile}" "${pcapFile}"`);
      } catch {
        console.log("::warning::etl2pcapng not found; copying ETL as-is");
        await fs.copyFile(etlFile, pcapFile);
      }
    }
  }

  // ── Finalize artifacts ──────────────────────────────────────────
  const pcapFile = path.join(captureDir, "raw-capture.pcap");
  const sslKeylog = path.join(captureDir, "sslkeys.log");
  const caCert = process.env.PCAP_CA_CERT || path.join(captureDir, ".mitmproxy", "mitmproxy-ca-cert.pem");
  const flowsFile = path.join(captureDir, "mitmproxy-flows");
  const fluxzyHarFile = path.join(captureDir, "fluxzy-capture.har");

  if (proxyTool === "fluxzy") {
    await filterHarInPlace(fluxzyHarFile);
  }

  const hasRawCapture = await exists(pcapFile);

  if (hasRawCapture) {
    const stat = await fs.stat(pcapFile);
    console.log(`PCAP file: ${pcapFile} (${stat.size} bytes)`);
  } else {
    console.log("No raw PCAP (raw-capture was disabled or tcpdump/netsh was not used)");
  }

  if (hasRawCapture && await exists(sslKeylog)) {
    const content = await fs.readFile(sslKeylog, "utf8");
    console.log(`SSL keylog: ${sslKeylog} (${content.split("\n").length} keys)`);
  }

  await appendOutput("pcap-file", pcapFile);
  await appendOutput("sslkeylog-file", sslKeylog);

  // ── Create bundle ───────────────────────────────────────────────
  let artifactName = getInput("artifact-name");
  if (!artifactName) {
    const ts = new Date().toISOString().replace(/[:-]/g, "").replace(/\..+/, "Z");
    artifactName = `pcap-${ts}`;
  }

  const bundleDir = path.join(captureDir, "bundle");
  await fs.mkdir(bundleDir, { recursive: true });

  // Always include proxy capture output; only include raw PCAP, SSL keys,
  // and CA cert when raw capture was active (tcpdump/netsh produced a file).
  const bundleFiles = proxyTool === "fluxzy" ? [fluxzyHarFile] : [flowsFile];
  if (hasRawCapture) {
    bundleFiles.push(pcapFile, sslKeylog, caCert);
  }

  await Promise.all(
    bundleFiles.map(async (f) => {
      if (await exists(f)) {
        await fs.copyFile(f, path.join(bundleDir, path.basename(f)));
      }
    })
  );

  const bundlePath = path.join(captureDir, `${artifactName}.tar.gz`);
  await new Promise((resolve, reject) => {
    const tar = spawn("tar", ["-czf", bundlePath, "-C", bundleDir, "."], {
      stdio: "inherit",
    });
    tar.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`tar exited with code ${code}`))
    );
    tar.on("error", reject);
  });

  const bundleSize = (await exists(bundlePath))
    ? (await fs.stat(bundlePath)).size
    : 0;
  console.log(`Bundle: ${bundlePath} (${bundleSize} bytes)`);

  await appendOutput("bundle-path", bundlePath);

  // ── Clear proxy env vars so later steps connect directly ────────
  const envFile = process.env.GITHUB_ENV;
  if (envFile) {
    const vars = [
      "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
      "NO_PROXY", "no_proxy",
      "NODE_EXTRA_CA_CERTS", "SSLKEYLOGFILE"
    ];
    const lines = vars.map((v) => `${v}=`).join("\n") + "\n";
    await fs.appendFile(envFile, lines);
    console.log("Cleared proxy/CA env vars from GITHUB_ENV");
  }

  // ── Save state for post step (S3 upload) ────────────────────────
  // Serialized to avoid interleaving in the state file
  await saveState("bundle-path", bundlePath);
  await saveState("artifact-name", artifactName);
  await saveState("s3-bucket", getInput("s3-bucket"));
  await saveState("s3-prefix", getInput("s3-prefix") || "pcap-captures");
  await saveState("s3-endpoint", getInput("s3-endpoint"));
  await saveState("capture-dir", captureDir);

  console.log("Capture stopped and bundled. S3 upload will run in post step.");
}

main().catch((e) => {
  console.error(`::error::${e.message}`);
  process.exit(1);
});
