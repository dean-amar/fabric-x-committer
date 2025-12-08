/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"
	"github.com/hyperledger/fabric-x-committer/utils/ordererconn"
	commontypes "github.com/hyperledger/fabric-x-common/api/types"
	"reflect"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/common/viperutil"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

// decoderHook contains custom unmarshalling for types not supported by default by mapstructure.
func decoderHook() viper.DecoderConfigOption {
	return viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		viperutil.StringSliceViaEnvDecodeHook, viperutil.ByteSizeDecodeHook, viperutil.OrdererEndpointDecoder,
		durationDecoder, serverDecoder, endpointDecoder, organizationParametersDecoder,
	))
}

func durationDecoder(dataType, targetType reflect.Type, rawData any) (result any, err error) {
	stringData, ok := viperutil.GetStringData(dataType, rawData)
	if !ok || targetType.Kind() != reflect.Int64 {
		return rawData, nil
	}
	duration, err := time.ParseDuration(stringData)
	return duration, errors.Wrap(err, "failed to parse duration")
}

func endpointDecoder(dataType, targetType reflect.Type, rawData any) (result any, err error) {
	stringData, ok := viperutil.GetStringData(dataType, rawData)
	if !ok || targetType != reflect.TypeOf(connection.Endpoint{}) {
		return rawData, nil
	}
	endpoint, err := connection.NewEndpoint(stringData)
	return endpoint, errors.Wrap(err, "failed to parse endpoint")
}

func serverDecoder(dataType, targetType reflect.Type, rawData any) (result any, err error) {
	stringData, ok := viperutil.GetStringData(dataType, rawData)
	if !ok || targetType != reflect.TypeOf(connection.ServerConfig{}) {
		return rawData, nil
	}
	endpoint, err := connection.NewEndpoint(stringData)
	var ret connection.ServerConfig
	if endpoint != nil {
		ret = connection.ServerConfig{Endpoint: *endpoint}
	}
	return ret, err
}

// organizationParametersDecoder parses raw string overrides into
// OrganizationParameters structs or slices of them.
// Supports ENV override formats like:
//
//	"msp-id=org0;id=0,broadcast,deliver,127.0.0.1:7050;ca=/client.pem"
//
// If applied to a slice type ([]OrganizationParameters), a single item
// override becomes a slice with one element.
func organizationParametersDecoder(dataType, targetType reflect.Type, raw any) (any, error) {
	// Convert input to string if possible
	stringData, ok := viperutil.GetStringData(dataType, raw)
	if !ok {
		return raw, nil
	}

	// SINGLE STRUCT TARGET
	if targetType == reflect.TypeOf(ordererconn.OrganizationParameters{}) {
		org, err := parseOrganizationParameters(stringData)
		if err != nil {
			return nil, err
		}
		return *org, nil
	}

	// SLICE TARGET: []OrganizationParameters or []*OrganizationParameters
	if targetType.Kind() == reflect.Slice &&
		(targetType.Elem() == reflect.TypeOf(ordererconn.OrganizationParameters{}) ||
			targetType.Elem() == reflect.TypeOf(&ordererconn.OrganizationParameters{})) {

		org, err := parseOrganizationParameters(stringData)
		if err != nil {
			return nil, err
		}

		sliceValue := reflect.MakeSlice(targetType, 1, 1)

		if targetType.Elem() == reflect.TypeOf(ordererconn.OrganizationParameters{}) {
			sliceValue.Index(0).Set(reflect.ValueOf(*org))
		} else {
			sliceValue.Index(0).Set(reflect.ValueOf(org))
		}
		return sliceValue.Interface(), nil
	}

	// Not applicable
	return raw, nil
}

func parseOrganizationParameters(raw string) (*ordererconn.OrganizationParameters, error) {
	parts := strings.Split(raw, ";")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OrganizationParameters string: %s", raw)
	}

	org := &ordererconn.OrganizationParameters{}

	// Part 1: msp-id=orgX
	if strings.HasPrefix(parts[0], "msp-id=") {
		org.MspID = strings.TrimPrefix(parts[0], "msp-id=")
	} else {
		return nil, fmt.Errorf("missing msp-id in override: %s", raw)
	}

	// Part 2: endpoint definition
	// Example: "id=0,broadcast,deliver,host:7050"
	ep, err := commontypes.ParseOrdererEndpoint(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed parsing orderer endpoint: %w", err)
	}
	org.Endpoints = []*commontypes.OrdererEndpoint{ep}

	// Part 3: optional CA cert
	if len(parts) > 2 && strings.HasPrefix(parts[2], "ca=") {
		org.CACerts = []string{strings.TrimPrefix(parts[2], "ca=")}
	}

	return org, nil
}
