"""mitmproxy inline filter addon.

Drops flows that don't match the configured filters BEFORE they are
written to the flow file, keeping the capture small on disk.

Configuration is read from environment variables:
  PCAP_FILTER_DOMAINS          comma-sep domain allowlist (glob patterns)
  PCAP_FILTER_EXCLUDE_DOMAINS  comma-sep domain denylist  (glob patterns)
  PCAP_FILTER_REFERERS         comma-sep referer patterns (glob patterns)
  PCAP_FILTER_CONTENT_TYPES    comma-sep content-type prefixes to keep
  PCAP_FILTER_MAX_BODY_SIZE    max response body in bytes (0 = no limit)
"""

from __future__ import annotations

import fnmatch
import logging
import os

from mitmproxy import ctx, http

logger = logging.getLogger(__name__)


def _csv(env_key: str) -> list[str]:
    raw = os.environ.get(env_key, "")
    return [v.strip() for v in raw.split(",") if v.strip()]


def _glob_match(value: str, patterns: list[str]) -> bool:
    lo = value.lower()
    return any(fnmatch.fnmatch(lo, p.lower()) for p in patterns)


class PcapFilter:
    def __init__(self) -> None:
        self.domain_allow = _csv("PCAP_FILTER_DOMAINS")
        self.domain_deny = _csv("PCAP_FILTER_EXCLUDE_DOMAINS")
        self.referer_patterns = _csv("PCAP_FILTER_REFERERS")
        self.ct_prefixes = _csv("PCAP_FILTER_CONTENT_TYPES")
        raw_max = os.environ.get("PCAP_FILTER_MAX_BODY_SIZE", "0")
        self.max_body = int(raw_max) if raw_max.isdigit() else 0

        self.stats = {
            "total": 0,
            "kept": 0,
            "filtered_domain": 0,
            "filtered_referer": 0,
            "filtered_content_type": 0,
            "filtered_size": 0,
        }

        active = any([
            self.domain_allow, self.domain_deny,
            self.referer_patterns, self.ct_prefixes, self.max_body,
        ])
        if active:
            logger.info(
                "PcapFilter active: domains=%s exclude=%s referers=%s "
                "content_types=%s max_body=%d",
                self.domain_allow, self.domain_deny,
                self.referer_patterns, self.ct_prefixes, self.max_body,
            )
        else:
            logger.info("PcapFilter loaded with no filters — all traffic passes through")

    def response(self, flow: http.HTTPFlow) -> None:
        self.stats["total"] += 1

        host = flow.request.pretty_host

        # Domain allowlist
        if self.domain_allow and not _glob_match(host, self.domain_allow):
            self.stats["filtered_domain"] += 1
            flow.kill()
            return

        # Domain denylist
        if self.domain_deny and _glob_match(host, self.domain_deny):
            self.stats["filtered_domain"] += 1
            flow.kill()
            return

        # Referer filter
        referer = flow.request.headers.get("referer", "")
        if self.referer_patterns and referer:
            if not _glob_match(referer, self.referer_patterns):
                self.stats["filtered_referer"] += 1
                flow.kill()
                return

        # Content-type filter
        if self.ct_prefixes and flow.response:
            ct = flow.response.headers.get("content-type", "")
            if ct and not any(ct.lower().startswith(p.lower()) for p in self.ct_prefixes):
                self.stats["filtered_content_type"] += 1
                flow.kill()
                return

        # Max body size
        if self.max_body > 0 and flow.response and flow.response.content:
            if len(flow.response.content) > self.max_body:
                self.stats["filtered_size"] += 1
                flow.kill()
                return

        self.stats["kept"] += 1

    def done(self) -> None:
        logger.info("PcapFilter stats: %s", self.stats)


addons = [PcapFilter()]
