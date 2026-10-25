#!/bin/sh
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir="$project_root/server/native/.build"
mkdir -p "$output_dir/cache"
/usr/bin/swiftc -O -module-cache-path "$output_dir/cache" "$project_root/server/native/Input.swift" -o "$output_dir/browser-native-input"
if [ "${1:-}" = "--verify" ] || [ "$#" = 0 ]; then
  printf '%s\n' '{"action":"status"}' | "$output_dir/browser-native-input"
fi
