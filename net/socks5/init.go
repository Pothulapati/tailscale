// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socks5

import "fmt"

const maxInitRequestSize = 257

// HandleInitPacket parses a request initiation packet
// and returns a slice that contains the acceptable auth methods
// for the client.
func HandleInitPacket(pkt []byte) error {
	sz := len(pkt)
	if sz < 3 {
		return fmt.Errorf("invalid read packet")
	}
	if pkt[0] != SOCKS5Version {
		return fmt.Errorf("incompatible SOCKS version")
	}
	count := int(pkt[1])
	if sz < count+2 {
		return fmt.Errorf("incorrect nmethods specified: %v vs %v", count, sz-2)
	}
	for _, m := range pkt[2:] {
		if m == noAuthRequired {
			return nil
		}
	}
	return fmt.Errorf("no acceptable auth methods")
}
