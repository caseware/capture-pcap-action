const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");

function getState(key) {
  return (process.env[`STATE_${key}`] || "").trim();
}

function appendOutput(key, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    const delimiter = `ghadelimiter_${crypto.randomUUID()}`;
    fs.appendFileSync(
      outputFile,
      `${key}<<${delimiter}\n${value}\n${delimiter}\n`
    );
  }
}

function post() {
  const bundlePath = getState("bundle-path");
  const artifactName = getState("artifact-name");
  const s3Bucket = getState("s3-bucket");
  const s3Prefix = getState("s3-prefix") || "pcap-captures";
  const s3Endpoint = getState("s3-endpoint");

  if (!bundlePath || !fs.existsSync(bundlePath)) {
    console.log("::warning::No bundle found for upload (capture may have failed)");
    return;
  }

  if (!s3Bucket) {
    console.log("::warning::No S3 bucket configured; skipping upload");
    return;
  }

  const s3Key = `${s3Prefix}/${artifactName}.tar.gz`;
  const s3Uri = `s3://${s3Bucket}/${s3Key}`;

  // Unset proxy env vars so S3 upload goes direct (may be local MinIO)
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
    execFileSync("aws", args, { stdio: "inherit", env: cleanEnv });
    console.log(`Upload complete: ${s3Uri}`);
    appendOutput("s3-uri", s3Uri);
  } catch (e) {
    console.error(`::error::S3 upload failed: ${e.message}`);
    process.exit(1);
  }
}

post();
