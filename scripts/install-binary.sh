#!/bin/sh
# Install only an already-extracted, trusted release binary. No downloads/state edits.
set -eu
if [ "$#" -ne 2 ]; then
    echo "usage: install-binary.sh /path/to/extracted/yip /absolute/install/path" >&2
    exit 2
fi
source_bin=$1
destination=$2
case "$destination" in /*) ;; *) echo "destination must be absolute" >&2; exit 2;; esac
[ -f "$source_bin" ] && [ -x "$source_bin" ] || { echo "source must be executable" >&2; exit 1; }
[ ! -d "$destination" ] || { echo "destination must be a file path" >&2; exit 2; }
version=$("$source_bin" version)
parent=$(dirname "$destination")
mkdir -p "$parent"
stage=$(mktemp "$parent/.yip-install.XXXXXX")
trap 'rm -f "$stage"' EXIT HUP INT TERM
cp "$source_bin" "$stage"
chmod 755 "$stage"
[ "$("$stage" version)" = "$version" ]
# Rename a new inode; never overwrite bytes of a running macOS executable.
if [ -e "$destination" ] || [ -L "$destination" ]; then
    backup="$destination.backup.$(date +%Y%m%dT%H%M%S).$$"
    cp -p "$destination" "$backup"
    echo "previous executable saved: $backup"
fi
mv -f "$stage" "$destination"
[ "$("$destination" version)" = "$version" ]
echo "installed $destination ($version); restart clients at the coordinated boundary"
