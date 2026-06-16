#!/bin/sh
exec "$1" "$(cat "$2")"
