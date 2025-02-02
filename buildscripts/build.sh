#!/bin/bash
#
# Copyright (c) 2015-2021 MinIO, Inc.
#
# This file is part of MinIO Object Storage stack
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

_init() {
    # Save release LDFLAGS
    LDFLAGS=$(go run buildscripts/gen-ldflags.go)

    if [ -z "$JMC_VAULT_ADDRESS" ] || [ -z "$JMC_SECRET_ENGINE" ] || [ -z "$JMC_SECRET_PATHS" ]; then
        echo "Vault configuration cannot be empty. Please check env variables."
        exit 1;
    fi

    # Extract release tag
    release_tag=$(echo $LDFLAGS | awk {'print $6'} | cut -f2 -d=)

    # Verify release tag.
    if [ -z "$release_tag" ]; then
        echo "Release tag cannot be empty. Please check return value of \`go run buildscripts/gen-ldflags.go\`"
        exit 1;
    fi

    # Extract release string.
    release_str=$(echo $MC_RELEASE | tr '[:upper:]' '[:lower:]')

    # Verify release string.
    if [ -z "$release_str" ]; then
        echo "Release string cannot be empty. Please set \`MC_RELEASE\` env variable."
        exit 1;
    fi

    # List of supported architectures
    SUPPORTED_OSARCH='linux/amd64 linux/ppc64le linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64'

    ## System binaries
    CP=`which cp`
    SHASUM=`which shasum`
    SHA256SUM="${SHASUM} -a 256"
    SED=`which sed`
}

go_build() {
    local osarch=$1
    os=$(echo $osarch | cut -f1 -d'/')
    arch=$(echo $osarch | cut -f2 -d'/')
    package=$(go list -f '{{.ImportPath}}')
    repo=$(basename -s .git $(git config --get remote.origin.url))
    echo -n "-->"
    printf "%15s:%s\n" "${osarch}" "${repo}"

    mkdir -p "$release_str/$os-$arch"

    # Release binary name
    release_bin="$release_str/$os-$arch/$repo.$release_tag"
    # Release binary downloadable name
    release_real_bin="$release_str/$os-$arch/$repo"

    # Release sha1sum name
    release_shasum="$release_str/$os-$arch/$repo.${release_tag}.shasum"
    # Release sha1sum default
    release_shasum_default="$release_str/$os-$arch/$repo.shasum"

    # Release sha256sum name
    release_sha256sum="$release_str/$os-$arch/$repo.${release_tag}.sha256sum"
    # Release sha256sum default
    release_sha256sum_default="$release_str/$os-$arch/$repo.sha256sum"

    # Go build to build the binary.
    export CGO_ENABLED=0
    export GOOS=$os
    export GOARCH=$arch
    go build -tags=kqueue -ldflags="${LDFLAGS}" -o $release_bin ## 

    # Create copy
    if [ $os == "windows" ]; then
        $CP -p $release_bin ${release_real_bin}.exe
    else
        $CP -p $release_bin $release_real_bin
    fi

    # Calculate sha1sum
    shasum_str=$(${SHASUM} ${release_bin})
    echo ${shasum_str} | $SED "s/$release_str\/$os-$arch\///g" > $release_shasum
    $CP -p $release_shasum $release_shasum_default

    # Calculate sha256sum
    sha256sum_str=$(${SHA256SUM} ${release_bin})
    echo ${sha256sum_str} | $SED "s/$release_str\/$os-$arch\///g" > $release_sha256sum
    $CP -p $release_sha256sum $release_sha256sum_default
}

main() {
    # Build releases.
    echo "Executing $release_str builds for OS: ${SUPPORTED_OSARCH}"
    echo  "Choose an OS Arch from the below"
    for osarch in ${SUPPORTED_OSARCH}; do
        echo ${osarch}
    done

    read -p "If you want to build for all, Just press Enter: " chosen_osarch
    if [ "$chosen_osarch" = "" ] || [ "$chosen_osarch" = "all" ]; then
        for each_osarch in ${SUPPORTED_OSARCH}; do
            go_build ${each_osarch}
        done
    else
        local found=0
        for each_osarch in ${SUPPORTED_OSARCH}; do
            if [ "$chosen_osarch" = "$each_osarch" ]; then
                found=1
            fi
        done
        if [ ${found} -eq 1 ]; then
            go_build ${chosen_osarch}
        else
            echo "Unknown architecture \"${chosen_osarch}\""
            exit 1
        fi
    fi

}

# Run main.
_init && main
