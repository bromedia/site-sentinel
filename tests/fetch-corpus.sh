#!/bin/sh
# Fetches the pinned false-positive corpus (tests/corpus-repos.txt) into DIR. Usage: fetch-corpus.sh DIR
set -eu
dir=$1
mkdir -p "$dir"
grep -v '^#' "$(dirname "$0")/corpus-repos.txt" | while read -r name url sha sparse; do
    [ -n "$name" ] || continue
    [ -d "$dir/$name/.git" ] && continue
    git init -q "$dir/$name"
    git -C "$dir/$name" remote add origin "$url"
    if [ -n "$sparse" ]; then
        git -C "$dir/$name" sparse-checkout set $sparse
        git -C "$dir/$name" fetch -q --depth 1 --filter=blob:none origin "$sha"
    else
        git -C "$dir/$name" fetch -q --depth 1 origin "$sha"
    fi
    git -C "$dir/$name" checkout -q FETCH_HEAD
    echo "fetched $name"
done
