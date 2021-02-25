// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package socks5 is an auth-less SOCKS5 server implementation
// for userspace networking in Tailscale.
package socks5

import (
	"net"

	"tailscale.com/types/logger"
)

// SOCKS5Version is the byte that represents the SOCKS version
// in requests.
const SOCKS5Version byte = 5

// Command are the bytes sent in SOCKS5 packets
// that represent the kind of connection the client needs.
type Command byte

// The set of valid SOCKS5 commans as described in RFC 1928.
const (
	Connect      Command = 1
	Bind         Command = 2
	UDPAssociate Command = 3
)

// Addr are the bytes sent in SOCKS5 packets
// that represent particular address types.
type Addr byte

// The set of valid SOCKS5 address types as defined in RFC 1928.
const (
	IPv4       Addr = 1
	DomainName Addr = 3
	IPv6       Addr = 4
)

// ListenAndServe creates a SOCKS5 server at the given address:port.
func ListenAndServe(address string, dialContext DialContext, logf logger.Logf) error {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			conn := Conn{client: c, dialContext: dialContext}
			err := conn.Run()
			if err != nil {
				logf("socks5: client connection failed: %s", err)
				conn.client.Close()
			}
		}()
	}
}
