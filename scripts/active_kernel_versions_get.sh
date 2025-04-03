#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

REAL_SCRIPT=$(realpath -e "${BASH_SOURCE[0]}")
SCRIPT_TOP="${SCRIPT_TOP:-$(dirname "${REAL_SCRIPT}")}"

VERSIONS=$(${SCRIPT_TOP}/active_kernel_versions.sh)
V=$(gum choose --no-limit ${VERSIONS})
echo "${V}"
exit
