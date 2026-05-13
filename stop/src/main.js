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

  // ── Stop mitmproxy ──────────────────────────────────────────────
  const mitmdumpPidFile = path.join(captureDir, "mitmdump.pid");
  if (await exists(mitmdumpPidFile)) {
    const pid = (await fs.readFile(mitmdumpPidFile, "utf8")).trim();
    console.log(`Stopping mitmdump (PID ${pid})...`);
    if (os.platform() === "win32") {
      await run(`taskkill /PID ${pid} /F`, { ignoreError: true });
    } else {
      await killProcess(pid);
    }
    await fs.unlink(mitmdumpPidFile);
    console.log("mitmdump stopped");

    const mitmdumpLog = path.join(captureDir, "mitmdump-stdout.log");
    if (await exists(mitmdumpLog)) {
      const log = (await fs.readFile(mitmdumpLog, "utf8")).trim();
      if (log) {
        console.log("::group::mitmdump log");
        console.log(log);
        console.log("::endgroup::");
      }
    }
  } else {
    console.log("::warning::mitmdump PID file not found");
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
  const caCert = path.join(captureDir, ".mitmproxy", "mitmproxy-ca-cert.pem");
  const flowsFile = path.join(captureDir, "mitmproxy-flows");

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

  // Always include mitmproxy flows; only include raw PCAP, SSL keys,
  // and CA cert when raw capture was active (tcpdump/netsh produced a file).
  const bundleFiles = [flowsFile];
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
