#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mika Tammi
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

nix build -L

PATH="$(dirname "$(basename "$0")")/result/bin:$PATH"

opentee-engine -f -c ./opentee.conf.myconf &
OPENTEE_PID="$!"
trap 'kill $OPENTEE_PID' EXIT

wait_for_open_tee_sock() {
	while :
	do
		if [ -S /tmp/open_tee_sock ]; then
			return 0
		fi
		echo "Waiting for Open-TEE socket to appear"
		sleep 1
	done
}
export -f wait_for_open_tee_sock
timeout 10s bash -c wait_for_open_tee_sock

set -x
# conn_test
# example_sha1
# pkcs11_test
property_test_ca
# sign_non_tee_ecdsa_256
# sign_tee_ecdsa_256
# svc_test
set +x

echo "Tests done"
