// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	noAuthRequired   byte = 0
	noAcceptableAuth byte = 255
)

// DialContext is the type of net.Dialer.DialContext. Conn owns a DialContext so that
// custom DialContexts (such as in gVisor netstack) can also be adapted to use here.
type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

// Conn represents a SOCKS5 connection for client to reach
// server.
type Conn struct {
	// The struct is filled by each of the internal
	// methods in turn as the transaction progresses.

	dialContext DialContext
	client      net.Conn
	server      net.Conn
	request     *request
}

// NewConn creates a new SOCKS5 connection that uses
// a custom dialing context to talk to the SOCKS5 server.
func NewConn(clientConn net.Conn, dialContext DialContext) *Conn {
	return &Conn{
		client:      clientConn,
		dialContext: dialContext,
	}
}

// Run starts the new connection.
func (conn *Conn) Run() error {
	buf := make([]byte, maxInitRequestSize)
	n, err := conn.client.Read(buf)
	if err != nil {
		return err
	}
	err = HandleInitPacket(buf[:n])
	if err != nil {
		conn.client.Write([]byte{SOCKS5Version, noAcceptableAuth})
		return err
	}
	conn.client.Write([]byte{SOCKS5Version, noAuthRequired})
	return conn.handleRequest()
}

func (conn *Conn) handleRequest() error {
	buf := make([]byte, maxRequestPacketSize)
	n, err := conn.client.Read(buf)
	if err != nil {
		return err
	}
	req, err := parseRequestFromPacket(buf[:n])
	if err != nil {
		buf, _ := createPacketFromResponse(&Response{reply: GeneralFailure})
		conn.client.Write(buf)
		return err
	}
	if req.command != Connect {
		buf, _ := createPacketFromResponse(&Response{reply: CommandNotSupported})
		conn.client.Write(buf)
		return fmt.Errorf("unsupported command %v", req.command)
	}
	conn.request = req
	return conn.createReply()
}

func (conn *Conn) createReply() error {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv, err := conn.dialContext(
		ctx,
		"tcp",
		fmt.Sprintf("%s:%v", conn.request.destination, conn.request.port),
	)
	if err != nil {
		buf, _ := createPacketFromResponse(&Response{reply: GeneralFailure})
		conn.client.Write(buf)
		return err
	}
	conn.server = srv
	serverAddr, serverPortStr, err := net.SplitHostPort(conn.server.LocalAddr().String())
	if err != nil {
		return err
	}
	serverPort, _ := strconv.Atoi(serverPortStr)
	go io.Copy(conn.client, conn.server)
	go io.Copy(conn.server, conn.client)

	var addrType Addr
	if ip := net.ParseIP(serverAddr); ip != nil {
		if ip.To4() != nil {
			addrType = IPv4
		} else {
			addrType = IPv6
		}
	} else {
		addrType = DomainName
	}

	buf, err := createPacketFromResponse(&Response{
		reply:    Success,
		addrType: addrType,
		bindAddr: serverAddr,
		bindPort: uint16(serverPort),
	})
	if err != nil {
		buf, _ = createPacketFromResponse(&Response{reply: GeneralFailure})
	}
	conn.client.Write(buf)
	return err
}
