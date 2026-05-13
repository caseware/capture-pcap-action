# Capture PCAP — GitHub Action

Capture e2e and regression test traffic as a **TLS-decryptable PCAP bundle** and upload it to S3.

## How it works

1. **`start/`** — Installs [mitmproxy](https://mitmproxy.org/) as a forward proxy, trusts its root CA on the OS, starts `tcpdump` (Linux) or `netsh trace` (Windows) for raw packet capture, loads an inline filter addon, and exports `HTTP_PROXY` / `HTTPS_PROXY` so downstream tests route through the proxy automatically.

2. **`stop/`** — Stops the proxy and packet capture, bundles the PCAP + TLS session keys (`SSLKEYLOGFILE`) + CA cert into a `.tar.gz`. The **S3 upload runs as a post step** so it executes even if subsequent steps fail.

Filtering happens **inline** in the mitmproxy addon — traffic that doesn't match the filter criteria is dropped before it hits the flow file, keeping captures small on disk.

The resulting bundle can be opened in [Wireshark](https://www.wireshark.org/) with full TLS decryption using the included `sslkeys.log` file.

## Usage

### Basic — wrap your e2e tests

```yaml
jobs:
  e2e:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/my-role
          aws-region: us-east-1

      # Start capturing BEFORE e2e tests
      - uses: caseware/capture-pcap-action/start@v1
        id: pcap

      # Your e2e tests run here — HTTP_PROXY/HTTPS_PROXY are set automatically
      - name: Run e2e tests
        run: npx playwright test

      # Stop capturing AFTER e2e tests — S3 upload runs as a post step
      - uses: caseware/capture-pcap-action/stop@v1
        with:
          s3-bucket: my-pcap-bucket
          s3-prefix: e2e/${{ github.run_id }}
```

### With domain filtering

Only capture traffic to your own services:

```yaml
      - uses: caseware/capture-pcap-action/start@v1
        with:
          filter-domains: '*.caseware.com,*.cwcloudtest.com'
          filter-exclude-domains: '*.analytics.google.com'
          filter-content-types: 'text/html,application/json'
          filter-max-body-size: '1048576'  # 1 MB
```

### Custom S3 endpoint (MinIO, LocalStack)

```yaml
      - uses: caseware/capture-pcap-action/stop@v1
        with:
          s3-bucket: test-bucket
          s3-endpoint: http://localhost:9000
```

## Inputs

### `start/`

| Input | Default | Description |
|-------|---------|-------------|
| `proxy-port` | `8080` | Port for the mitmproxy forward proxy |
| `capture-dir` | `$RUNNER_TEMP/pcap-capture` | Directory for capture artifacts |
| `process-name` | _(empty)_ | _(reserved, not yet implemented)_ Process name filter |
| `mitmproxy-version` | `11.1.3` | mitmproxy version to install |
| `filter-domains` | _(empty)_ | Domain allowlist (comma-sep, globs OK, e.g. `*.caseware.com`) |
| `filter-exclude-domains` | _(empty)_ | Domain denylist (comma-sep, globs OK) |
| `filter-referers` | _(empty)_ | Referer patterns to keep (comma-sep, globs OK) |
| `filter-content-types` | _(empty)_ | Content-type prefixes to keep (e.g. `text/html,application/json`) |
| `filter-max-body-size` | `0` | Max response body size in bytes (0 = no limit) |

### `stop/`

| Input | Default | Description |
|-------|---------|-------------|
| `capture-dir` | _(from env)_ | Capture directory (auto-detected from start action) |
| `s3-bucket` | **required** | S3 bucket name |
| `s3-prefix` | `pcap-captures` | S3 key prefix |
| `s3-endpoint` | _(empty)_ | Custom S3 endpoint URL |
| `artifact-name` | _(timestamped)_ | Name for the capture bundle |

> **Note:** The stop action's S3 upload runs as a **post step** — it will execute
> at job cleanup time even if later steps fail.

## Outputs

### `start/`

| Output | Description |
|--------|-------------|
| `capture-dir` | Path to the capture artifacts directory |
| `ca-cert` | Path to the mitmproxy root CA PEM |
| `proxy-url` | Proxy URL (`http://127.0.0.1:<port>`) |

### `stop/`

| Output | Description |
|--------|-------------|
| `pcap-file` | Path to the raw PCAP file |
| `sslkeylog-file` | Path to the TLS session keys file |
| `bundle-path` | Local path to the `.tar.gz` bundle |
| `s3-uri` | S3 URI of the uploaded bundle _(set in post step)_ |

## Inline filtering

Filtering is applied **inside the mitmproxy addon** (`scripts/filter-addon.py`)
at request/response time. Filtered flows are killed immediately — they never
reach the flow file on disk. This means:

- The flow file only contains traffic that passes the filter
- No post-processing ETL step is needed
- The resulting bundle is smaller from the start

The raw PCAP (tcpdump/netsh) captures all packets regardless of the filter.
This is by design — the PCAP is useful for debugging network issues that the
proxy filter might mask. Use the `sslkeys.log` + PCAP in Wireshark for full
visibility, and the mitmproxy flows for the filtered view.

## Decrypting the PCAP in Wireshark

1. Download and extract the bundle from S3
2. Open `raw-capture.pcap` in Wireshark
3. Go to **Edit > Preferences > Protocols > TLS**
4. Set **(Pre)-Master-Secret log filename** to `sslkeys.log`
5. All TLS traffic will be decrypted

## Platform support

| Feature | Linux | Windows |
|---------|-------|---------|
| mitmproxy TLS interception | pip install | pip install |
| Inline flow filtering | addon | addon |
| Raw packet capture | tcpdump | netsh trace + etl2pcapng |
| CA trust | update-ca-certificates | Import-Certificate |
| S3 upload (post step) | aws cli | aws cli |

## Integration with existing workflows

### pr-workflow.yml (e2e tests)

```yaml
      - uses: caseware/capture-pcap-action/start@v1
        with:
          filter-domains: '*.caseware.com,*.cwcloudtest.com'

      # ... existing e2e test steps ...

      - uses: caseware/capture-pcap-action/stop@v1
        with:
          s3-bucket: ${{ vars.PCAP_S3_BUCKET }}
          s3-prefix: pr/${{ github.event.pull_request.number }}
```

### nightly-trunk-regression.yml

```yaml
      - uses: caseware/capture-pcap-action/start@v1

      # ... existing regression test steps ...

      - uses: caseware/capture-pcap-action/stop@v1
        with:
          s3-bucket: ${{ vars.PCAP_S3_BUCKET }}
          s3-prefix: nightly/${{ github.run_id }}
```
