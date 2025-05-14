/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
)

// Endpoint describes a remote endpoint.
type Endpoint struct {
	Host string `mapstructure:"host" json:"host,omitempty" yaml:"host,omitempty"`
	Port int    `mapstructure:"port" json:"port,omitempty" yaml:"port,omitempty"`
}

// Empty returns true if no port is assigned.
func (e *Endpoint) Empty() bool {
	return e.Port == 0
}

// Address returns a string representation of the endpoint's address.
func (e *Endpoint) Address() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

// String returns a string representation of the endpoint.
func (e *Endpoint) String() string {
	return e.Address()
}

// GetHost returns the host of the endpoint.
func (e *Endpoint) GetHost() string { return e.Host }

// CreateEndpointHP parses an endpoint from give host and port.
// It panics if it fails to parse.
func CreateEndpointHP(host, port string) *Endpoint {
	convertedPort, err := strconv.Atoi(port)
	if err != nil {
		panic(errors.New("could not convert port to integer"))
	}
	return &Endpoint{
		Host: host,
		Port: convertedPort,
	}
}

// CreateEndpoint parses an endpoint from an address string.
// It panics if it fails to parse.
func CreateEndpoint(value string) *Endpoint {
	endpoint, err := NewEndpoint(value)
	if err != nil {
		panic(errors.Wrap(err, "could not create endpoint"))
	}
	return endpoint
}

// NewEndpoint parses an endpoint from an address string.
func NewEndpoint(value string) (*Endpoint, error) {
	if len(value) == 0 {
		return &Endpoint{}, nil
	}
	vals := strings.Split(value, ":")
	if len(vals) != 2 {
		return nil, errors.New("not in format: 1.2.3.4:5")
	}
	host := vals[0]
	port, err := strconv.Atoi(vals[1])
	if err != nil {
		return nil, err
	}
	return &Endpoint{Host: host, Port: port}, nil
}

// NewLocalHost returns a default endpoint "localhost:0".
func NewLocalHost() *Endpoint {
	return &Endpoint{Host: "localhost"}
}
