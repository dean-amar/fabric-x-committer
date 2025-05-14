/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package grpcerror

import (
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HasCode returns true if the rpcErr holds the given code.
func HasCode(rpcErr error, code codes.Code) bool {
	if rpcErr == nil {
		return false
	}
	return GetCode(rpcErr) == code
}

// GetCode returns GRPC error code.
func GetCode(rpcErr error) codes.Code {
	if rpcErr == nil {
		return codes.OK
	}

	errStatus, ok := status.FromError(rpcErr)
	if !ok {
		return codes.OK
	}

	return errStatus.Code()
}

// WrapInternalError creates a grpc error with a [codes.Internal] status code for a given error.
func WrapInternalError(err error) error {
	return wrap(codes.Internal, err)
}

// WrapInvalidArgument creates a grpc error with a [codes.InvalidArgument] status code for a given error.
func WrapInvalidArgument(err error) error {
	return wrap(codes.InvalidArgument, err)
}

// WrapCancelled creates a grpc error with a [codes.Canceled] status code for a given error.
func WrapCancelled(err error) error {
	return wrap(codes.Canceled, err)
}

func wrap(c codes.Code, err error) error {
	if err == nil {
		return nil
	}
	return status.Error(c, err.Error())
}

// FilterUnavailableErrorCode rpc error that caused due to transient connectivity issue.
func FilterUnavailableErrorCode(rpcErr error) error {
	code := GetCode(rpcErr)
	if slices.Contains([]codes.Code{codes.Unavailable, codes.DeadlineExceeded}, code) {
		return nil
	}
	return rpcErr
}
