#!/usr/bin/env bash
# Install only checksum-locked Linux AMD64 CI tools into a caller-owned directory.
set -euo pipefail

lock_file="tools.lock.json"
install_dir="${PWD}/.ci-tools/bin"

usage() {
  echo "usage: $0 [--lock-file PATH] [--install-dir PATH]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --lock-file)
      lock_file="$2"
      shift 2
      ;;
    --install-dir)
      install_dir="$2"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [ -n "${SETUP_CI_TOOLS_PLATFORM:-}" ]; then
  platform="$SETUP_CI_TOOLS_PLATFORM"
elif [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; then
  platform="linux_amd64"
else
  platform="unsupported"
fi

if [ "$platform" != "linux_amd64" ]; then
  echo "setup-ci-tools supports only locked linux_amd64 assets" >&2
  exit 2
fi

if [ ! -f "$lock_file" ]; then
  echo "tool lock not found" >&2
  exit 2
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

while IFS=$'\t' read -r name asset checksum url; do
  archive="$work_dir/$asset"
  curl --fail --location --silent --show-error --output "$archive" "$url"
  actual_checksum="$(shasum -a 256 "$archive" | awk '{print $1}')"
  if [ "$actual_checksum" != "$checksum" ]; then
    echo "checksum verification failed for $name" >&2
    exit 1
  fi

  stage="$work_dir/$name"
  mkdir -p "$stage"
  case "$asset" in
    *.zip)
      unzip -q "$archive" -d "$stage"
      ;;
    *.tar.gz)
      tar -xzf "$archive" -C "$stage"
      ;;
    *.tar.xz)
      tar -xJf "$archive" -C "$stage"
      ;;
    *)
      install -m 0755 "$archive" "$stage/$name"
      ;;
  esac

  candidate="$(find "$stage" -type f -name "$name" -print -quit)"
  if [ -z "$candidate" ]; then
    echo "locked asset did not contain expected executable for $name" >&2
    exit 1
  fi
  mkdir -p "$install_dir"
  install -m 0755 "$candidate" "$install_dir/$name"
done < <(
  python3 - "$lock_file" "$platform" <<'PY'
import json
import pathlib
import sys

lock_path = pathlib.Path(sys.argv[1])
platform = sys.argv[2]
try:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    tools = lock["tools"]
except (OSError, ValueError, KeyError, TypeError) as error:
    raise SystemExit(f"invalid tool lock: {error}")

if platform != "linux_amd64" or platform not in lock.get("platforms", []):
    raise SystemExit("requested platform is not locked")

for name in sorted(tools):
    tool = tools[name]
    version = tool.get("version")
    archive = tool.get("archives", {}).get(platform)
    if not isinstance(version, str) or not isinstance(archive, dict):
        raise SystemExit(f"unlocked tool entry: {name}")
    asset = archive.get("asset")
    checksum = archive.get("sha256")
    url = archive.get("url")
    if not all(isinstance(value, str) and value for value in (asset, checksum, url)):
        raise SystemExit(f"unlocked asset entry: {name}")
    if len(checksum) != 64 or any(char not in "0123456789abcdef" for char in checksum.lower()):
        raise SystemExit(f"invalid checksum lock: {name}")
    if version not in asset or not url.endswith("/" + asset):
        raise SystemExit(f"version does not match locked asset: {name}")
    print("\t".join((name, asset, checksum, url)))
PY
)
