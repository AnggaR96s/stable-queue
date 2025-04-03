#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

REAL_SCRIPT=$(realpath -e "${BASH_SOURCE[0]}")
SCRIPT_TOP="${SCRIPT_TOP:-$(dirname "${REAL_SCRIPT}")}"

for VERSION in $(cat ${SCRIPT_TOP}/../active_kernel_versions); do
	echo -n "${VERSION} "
done
echo ""

