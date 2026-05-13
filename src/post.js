const { execFile: execFileCb } = require("node:child_process");
const { promisify } = require("node:util");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");

const execFile = promisify(execFileCb);

function getState(key) {
  return (process.env[`STATE_${key}`] || "").trim();
}

async function appendOutput(key, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    const delimiter = `ghadelimiter_${crypto.randomUUID()}`;
    await fs.appendFile(
      outputFile,
      `${key}<<${delimiter}\n${value}\n${delimiter}\n`
    );
  }
}

async function exists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

async function post() {
  const bundlePath = getState("bundle-path");
  const artifactName = getState("artifact-name");
  const s3Bucket = getState("s3-bucket");
  const s3Prefix = getState("s3-prefix") || "pcap-captures";
  const s3Endpoint = getState("s3-endpoint");

  if (!bundlePath || !(await exists(bundlePath))) {
    console.log("::warning::No bundle found for upload (capture may have failed)");
    return;
  }

  if (!s3Bucket) {
    console.log("::warning::No S3 bucket configured; skipping upload");
    return;
  }

  const now = new Date();
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(now.getUTCDate()).padStart(2, "0");
  const s3Key = `${s3Prefix}/${yyyy}/${mm}/${dd}/${artifactName}.tar.gz`;
  const s3Uri = `s3://${s3Bucket}/${s3Key}`;

  const cleanEnv = { ...process.env };
  delete cleanEnv.HTTP_PROXY;
  delete cleanEnv.HTTPS_PROXY;
  delete cleanEnv.http_proxy;
  delete cleanEnv.https_proxy;

  const args = ["s3", "cp", bundlePath, s3Uri];
  if (s3Endpoint) {
    args.push("--endpoint-url", s3Endpoint);
  }

  console.log(`Uploading ${bundlePath} -> ${s3Uri}`);
  try {
    await execFile("aws", args, { env: cleanEnv });
    console.log(`Upload complete: ${s3Uri}`);
    await appendOutput("s3-uri", s3Uri);
  } catch (e) {
    console.error(`::error::S3 upload failed: ${e.message}`);
    process.exit(1);
  }
}

post().catch((e) => {
  console.error(`::error::${e.message}`);
  process.exit(1);
});
