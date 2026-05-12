const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

function appendOutput(key, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    fs.appendFileSync(outputFile, `${key}=${value}\n`);
  }
}

function saveState(key, value) {
  const stateFile = process.env.GITHUB_STATE;
  if (stateFile) {
    fs.appendFileSync(stateFile, `${key}=${value}\n`);
  }
}

function getInput(name) {
  const envName = `INPUT_${name.replace(/-/g, "_").toUpperCase()}`;
  return (process.env[envName] || "").trim();
}

function run(cmd, opts = {}) {
  console.log(`> ${cmd}`);
  try {
    execSync(cmd, { stdio: "inherit", ...opts });
  } catch (e) {
    if (!opts.ignoreError) throw e;
  }
}

function main() {
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
  if (fs.existsSync(mitmdumpPidFile)) {
    const pid = fs.readFileSync(mitmdumpPidFile, "utf8").trim();
    console.log(`Stopping mitmdump (PID ${pid})...`);
    if (os.platform() === "win32") {
      run(`taskkill /PID ${pid} /F`, { ignoreError: true });
    } else {
      run(`kill ${pid} || true`, { ignoreError: true, shell: "/bin/bash" });
      run("sleep 2", { shell: "/bin/bash" });
      run(`kill -9 ${pid} 2>/dev/null || true`, {
        ignoreError: true,
        shell: "/bin/bash",
      });
    }
    fs.unlinkSync(mitmdumpPidFile);
    console.log("mitmdump stopped");
  } else {
    console.log("::warning::mitmdump PID file not found");
  }

  // ── Stop tcpdump / netsh ────────────────────────────────────────
  if (os.platform() !== "win32") {
    const tcpdumpPidFile = path.join(captureDir, "tcpdump.pid");
    if (fs.existsSync(tcpdumpPidFile)) {
      const pid = fs.readFileSync(tcpdumpPidFile, "utf8").trim();
      console.log(`Stopping tcpdump (PID ${pid})...`);
      run(`sudo kill ${pid} 2>/dev/null || true`, {
        ignoreError: true,
        shell: "/bin/bash",
      });
      run("sleep 2", { shell: "/bin/bash" });
      run(`sudo kill -9 ${pid} 2>/dev/null || true`, {
        ignoreError: true,
        shell: "/bin/bash",
      });
      fs.unlinkSync(tcpdumpPidFile);
      console.log("tcpdump stopped");
    }
  } else {
    console.log("Stopping netsh trace...");
    run("netsh trace stop", { ignoreError: true });

    const etlFile = path.join(captureDir, "raw-capture.etl");
    const pcapFile = path.join(captureDir, "raw-capture.pcap");
    if (fs.existsSync(etlFile)) {
      try {
        run(`etl2pcapng "${etlFile}" "${pcapFile}"`);
      } catch {
        console.log("::warning::etl2pcapng not found; copying ETL as-is");
        fs.copyFileSync(etlFile, pcapFile);
      }
    }
  }

  // ── Finalize artifacts ──────────────────────────────────────────
  const pcapFile = path.join(captureDir, "raw-capture.pcap");
  const sslKeylog = path.join(captureDir, "sslkeys.log");
  const caCert = path.join(captureDir, ".mitmproxy", "mitmproxy-ca-cert.pem");
  const flowsFile = path.join(captureDir, "mitmproxy-flows");

  if (fs.existsSync(pcapFile)) {
    const size = fs.statSync(pcapFile).size;
    console.log(`PCAP file: ${pcapFile} (${size} bytes)`);
  } else {
    console.log("::warning::PCAP file not found");
  }

  if (fs.existsSync(sslKeylog)) {
    const lines = fs.readFileSync(sslKeylog, "utf8").split("\n").length;
    console.log(`SSL keylog: ${sslKeylog} (${lines} keys)`);
  }

  appendOutput("pcap-file", pcapFile);
  appendOutput("sslkeylog-file", sslKeylog);

  // ── Create bundle ───────────────────────────────────────────────
  let artifactName = getInput("artifact-name");
  if (!artifactName) {
    const ts = new Date().toISOString().replace(/[:-]/g, "").replace(/\..+/, "Z");
    artifactName = `pcap-${ts}`;
  }

  const bundleDir = path.join(captureDir, "bundle");
  fs.mkdirSync(bundleDir, { recursive: true });

  for (const f of [pcapFile, sslKeylog, flowsFile, caCert]) {
    if (fs.existsSync(f)) {
      fs.copyFileSync(f, path.join(bundleDir, path.basename(f)));
    }
  }

  const bundlePath = path.join(captureDir, `${artifactName}.tar.gz`);
  if (os.platform() !== "win32") {
    run(`tar -czf "${bundlePath}" -C "${bundleDir}" .`);
  } else {
    run(`tar -czf "${bundlePath}" -C "${bundleDir}" .`, { shell: true });
  }

  const bundleSize = fs.existsSync(bundlePath)
    ? fs.statSync(bundlePath).size
    : 0;
  console.log(`Bundle: ${bundlePath} (${bundleSize} bytes)`);

  appendOutput("bundle-path", bundlePath);

  // ── Save state for post step (S3 upload) ────────────────────────
  saveState("bundle-path", bundlePath);
  saveState("artifact-name", artifactName);
  saveState("s3-bucket", getInput("s3-bucket"));
  saveState("s3-prefix", getInput("s3-prefix") || "pcap-captures");
  saveState("s3-endpoint", getInput("s3-endpoint"));
  saveState("capture-dir", captureDir);

  console.log("Capture stopped and bundled. S3 upload will run in post step.");
}

main();
