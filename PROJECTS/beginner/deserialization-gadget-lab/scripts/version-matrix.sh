#!/usr/bin/env bash
# ©AngelaMos | 2026
# version-matrix.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROBE="${HERE}/test/support/matrix_probe.rb"
RENDER="${HERE}/scripts/render_matrix.rb"
OUT="${HERE}/tmp/matrix.jsonl"
RENDER_IMAGE="ruby:4.0-slim"

IMAGES=(
    "ruby:3.1-slim"
    "ruby:3.2-slim"
    "ruby:3.3-slim"
    "ruby:3.4-slim"
    "ruby:4.0.2-slim"
    "ruby:4.0-slim"
)

if [[ $# -gt 0 ]]; then
    IMAGES=("$@")
fi

mkdir -p "${HERE}/tmp"
: >"${OUT}"

echo "probing ${#IMAGES[@]} images"

for image in "${IMAGES[@]}"; do
    printf '  %-18s ' "${image}"

    if ! docker image inspect "${image}" >/dev/null 2>&1; then
        if ! docker pull -q "${image}" >/dev/null 2>&1; then
            echo "UNAVAILABLE"
            continue
        fi
    fi

    if result=$(docker run --rm --network none \
        -e "MATRIX_IMAGE=${image}" \
        -v "${PROBE}:/probe.rb:ro" \
        "${image}" ruby /probe.rb 2>/dev/null); then
        echo "${result}" >>"${OUT}"
        echo "ok"
    else
        echo "PROBE FAILED"
    fi
done

echo
docker run --rm --network none \
    -v "${OUT}:/matrix.jsonl:ro" \
    -v "${RENDER}:/render.rb:ro" \
    "${RENDER_IMAGE}" ruby /render.rb /matrix.jsonl
