#!/usr/bin/env bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -euxo pipefail

docker_cmd=$1
version=$2
namespace=$3
dockerfile_release_dir=$4
multiplatform=$5
arch_bin_dir=$6
image_prefix=committer-

function build_image() {
  local service_name=$1
  local image_name=$2
  local service_ports=$3
  local manifest_name=${namespace}/${image_prefix}${image_name}:${version}
  local cmd=(
    "${docker_cmd}" build
    -f "${dockerfile_release_dir}/Dockerfile"
    --build-arg SERVICE_NAME="${service_name}"
    --build-arg PORTS="${service_ports}"
    --build-arg ARCHBIN_PATH="${arch_bin_dir}"
  )

  if [ "${multiplatform}" = true ]; then
    # Multi-platform build
    ${docker_cmd} images "${manifest_name}" -q -a | xargs "${docker_cmd}" rmi
    ${docker_cmd} manifest create "${manifest_name}"
    "${cmd[@]}" --jobs=4 --platform linux/amd64,linux/arm64,linux/s390x --manifest "${manifest_name}" .
  else
    # Current platform build
    "${cmd[@]}" -t "${manifest_name}" .
  fi
}

# to build the sc binaries for z, make sure you use the
# following make command before building the container images
#
# make GOOS=linux GOARCH=s390x build

# build container images
build_image sidecar sidecar "4001 2114"
build_image coordinator coordinator "9001 2119"
build_image signatureverifier signature-verifier "5001 2115"
build_image validatorpersister validator-persister "6001 2116"
build_image loadgen loadgen "2110"
build_image queryexecutor query-executor "7001 2117"

${docker_cmd} images | grep ${image_prefix}
