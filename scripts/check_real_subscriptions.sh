#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${SKYHOOK_TEST_SUBSCRIPTION_URLS:-}" ]]; then
  echo "Set SKYHOOK_TEST_SUBSCRIPTION_URLS to newline or comma separated subscription URLs." >&2
  exit 1
fi

cargo test --test real_subscription_compat external_subscription_urls_parse_without_persisting_source -- --ignored --nocapture
