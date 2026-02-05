#!/bin/sh

nitriding -fqdn example.com -ext-pub-port 10443 -intport 8080 -wait-for-app &
echo "[sh] Started nitriding."

sleep 1

service
echo "[sh] Ran Go binary."
