#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$repo/cmd/switchboard" && go build -o "$tmp/yip-switchboard" .)
case ${1:-} in
    --check|--demo) "$tmp/yip-switchboard" "$@" ;;
    *) if [ -n "${YIP_SWITCHBOARD_BIN:-}" ]; then
           YIP_SWITCHBOARD_DIR=${YIP_SWITCHBOARD_DIR:-"$PWD"} "$tmp/yip-switchboard" "$@"
           exit
       fi
       (cd "$repo" && go build -o "$tmp/yip" .)
       "$tmp/yip" switchboard "$@" ;;
esac
