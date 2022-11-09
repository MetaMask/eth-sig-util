#!/usr/bin/env bash

set -x
set -e
set -o pipefail

if [[ -n $SKIP_PREPACK ]]; then
  echo "Notice: skipping prepack."
  exit 0
fi

yarn build:clean
