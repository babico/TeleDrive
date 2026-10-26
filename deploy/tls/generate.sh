#!/usr/bin/env bash
# TeleDrive — generate per-listener TLS material under the ./data mount.
#
# TLS is ENV-ONLY deployment plumbing. This script only creates files and
# prints the environment lines to put in docker-compose/.env; it never
# edits config/config.yaml.
#
# Two independent listeners, one certificate pair each (or one shared pair):
#   WebUI / REST : TELEDRIVE_SSL_CERTFILE    / TELEDRIVE_SSL_KEYFILE
#   S3 gateway   : TELEDRIVE_S3_SSL_CERTFILE / TELEDRIVE_S3_SSL_KEYFILE
#
# A combined .pem (certificate chain + private key in one file) works with
# only the CERTFILE variable set — uvicorn accepts that. A split pair needs
# both variables.
#
# Files land in ./config/ssl, which is already bind-mounted at /config
# inside the container (as /config/ssl), so no extra volume is required.
#
# Usage:
#   ./deploy/tls/generate.sh                      # split pair, both listeners
#   ./deploy/tls/generate.sh --combined           # one combined .pem
#   ./deploy/tls/generate.sh --san 10.0.0.5 --days 825
#   ./deploy/tls/generate.sh --force              # overwrite existing files
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT}/config/ssl"
DAYS=825
COMBINED=0
FORCE=0
HOSTNAME_DEFAULT="$(hostname 2>/dev/null || echo teledrive)"
SANS=()
CONTAINER_OUT="/config/ssl"

while [ $# -gt 0 ]; do
  case "$1" in
    --combined) COMBINED=1; shift ;;
    --force) FORCE=1; shift ;;
    --days) DAYS="${2:?--days needs a value}"; shift 2 ;;
    --san) SANS+=("${2:?--san needs a value}"); shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

CRT="${OUT_DIR}/server.crt"
KEY="${OUT_DIR}/server.key"
PEM="${OUT_DIR}/server.pem"

if [ "${FORCE}" -ne 1 ] && { [ -f "${CRT}" ] || [ -f "${PEM}" ]; }; then
  echo "TLS material already present in ${OUT_DIR} (use --force to replace)" >&2
fi

mkdir -p "${OUT_DIR}"
chmod 700 "${OUT_DIR}"

# SAN list: localhost/loopback always, the host name, then any --san value.
SAN_ENTRIES="DNS:localhost,DNS:${HOSTNAME_DEFAULT},IP:127.0.0.1"
for extra in "${SANS[@]:-}"; do
  [ -z "${extra}" ] && continue
  if [[ "${extra}" =~ ^[0-9.]+$ ]]; then
    SAN_ENTRIES="${SAN_ENTRIES},IP:${extra}"
  else
    SAN_ENTRIES="${SAN_ENTRIES},DNS:${extra}"
  fi
done

if [ "${FORCE}" -eq 1 ] || [ ! -f "${CRT}" ]; then
  tmp_cfg="$(mktemp)"
  trap 'rm -f "${tmp_cfg}"' EXIT
  cat >"${tmp_cfg}" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
O = TeleDrive
CN = ${HOSTNAME_DEFAULT}
[v3]
subjectAltName = ${SAN_ENTRIES}
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days "${DAYS}" -config "${tmp_cfg}" \
    -keyout "${KEY}" -out "${CRT}" >/dev/null 2>&1
  chmod 600 "${KEY}"
  chmod 644 "${CRT}"
  echo "generated split pair:" >&2
  echo "  ${CRT}" >&2
  echo "  ${KEY}" >&2
fi

if [ "${COMBINED}" -eq 1 ] || [ -f "${PEM}" ]; then
  cat "${KEY}" "${CRT}" >"${PEM}.tmp"
  mv "${PEM}.tmp" "${PEM}"
  chmod 600 "${PEM}"
  echo "generated combined PEM:" >&2
  echo "  ${PEM}" >&2
fi

echo
echo "Add these to the docker-compose environment (or .env), then restart:"
echo "# WebUI / REST listener"
echo "TELEDRIVE_SSL_CERTFILE=${CONTAINER_OUT}/$( [ "${COMBINED}" -eq 1 ] && echo server.pem || echo server.crt )"
[ "${COMBINED}" -eq 0 ] && echo "TELEDRIVE_SSL_KEYFILE=${CONTAINER_OUT}/server.key"
echo "# S3 gateway listener (independent; the same files work)"
echo "TELEDRIVE_S3_SSL_CERTFILE=${CONTAINER_OUT}/$( [ "${COMBINED}" -eq 1 ] && echo server.pem || echo server.crt )"
[ "${COMBINED}" -eq 0 ] && echo "TELEDRIVE_S3_SSL_KEYFILE=${CONTAINER_OUT}/server.key"
echo
echo "Verify with:"
echo "  openssl s_client -connect 127.0.0.1:\${TELEDRIVE_S3_PORT:-9000} </dev/null 2>/dev/null | openssl x509 -noout -subject -dates"
