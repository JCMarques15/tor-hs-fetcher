#!/usr/bin/env bash

echo "$1" | base64 -d | sha1sum - | cut -c 1-20 | xxd -r -p | base32 - | tr 'A-Z' 'a-z'   
