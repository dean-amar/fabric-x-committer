#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -ex
curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protoc-29.3-linux-x86_64.zip
unzip -j protoc-29.3-linux-x86_64.zip 'bin/*' -d "$HOME/bin"

go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.33
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3
