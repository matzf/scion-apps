// Copyright 2021 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

// XXX: export errors, also generally revisit error wrapping/handling
var errNoPath error = errors.New("no path")

func DialUDP(ctx context.Context, local *net.UDPAddr, remote UDPAddr,
	policy Policy, selector Selector) (net.Conn, error) {

	local, err := defaultLocalAddr(local)
	if err != nil {
		return nil, err
	}

	if selector == nil {
		selector = &DefaultSelector{}
	}

	raw, slocal, err := openScionPacketConn(ctx, local, selector)
	if err != nil {
		return nil, err
	}
	// XXX: dont do this for dst in local IA!
	var subscriber *pathRefreshSubscriber
	if remote.IA != slocal.IA {
		subscriber, err = openPathRefreshSubscriber(ctx, remote, policy, selector)
		if err != nil {
			return nil, err
		}
	}
	return &connectedConn{
		scionUDPConn: scionUDPConn{
			raw: raw,
		},
		local:      slocal,
		remote:     remote,
		subscriber: subscriber,
		Selector:   selector,
	}, nil
}

// XXX: connectedConn, _great_ name :/
// XXX: export (to add extended API)?
type connectedConn struct {
	scionUDPConn

	local      UDPAddr
	remote     UDPAddr
	subscriber *pathRefreshSubscriber
	Selector   Selector
}

func (c *connectedConn) SetPolicy(policy Policy) {
	c.subscriber.setPolicy(policy)
}

func (c *connectedConn) LocalAddr() net.Addr {
	return c.local
}

func (c *connectedConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *connectedConn) Write(b []byte) (int, error) {
	var path *Path
	if c.local.IA != c.remote.IA {
		path = c.Selector.Path()
		if path == nil {
			return 0, errNoPath
		}
	}
	return c.scionUDPConn.writeMsg(c.local, c.remote, path, b)
}

func (c *connectedConn) WritePath(path *Path, b []byte) (int, error) {
	return c.scionUDPConn.writeMsg(c.local, c.remote, path, b)
}

func (c *connectedConn) Read(b []byte) (int, error) {
	for {
		n, remote, _, err := c.scionUDPConn.readMsg(b)
		if err != nil {
			return n, err
		}
		if !remote.Equal(c.remote) {
			continue // connected! Ignore spurious packets from wrong source
		}
		return n, err
	}
}

func (c *connectedConn) ReadPath(b []byte) (int, *Path, error) {
	for {
		n, remote, fwPath, err := c.scionUDPConn.readMsg(b)
		if err != nil {
			return n, nil, err
		}
		if !remote.Equal(c.remote) {
			continue // connected! Ignore spurious packets from wrong source
		}
		path, err := reversePathFromForwardingPath(c.remote.IA, c.local.IA, fwPath)
		if err != nil {
			continue // just drop the packet if there is something wrong with the path
		}
		return n, path, nil
	}
}

func (c *connectedConn) Close() error {
	_ = c.subscriber.Close()
	return c.scionUDPConn.Close()
}

//////////////////// subscriber

// enterprise path setter
type pathSetter interface {
	SetPaths([]*Path)
}

type pathRefreshSubscriber struct {
	remote UDPAddr
	policy Policy
	target pathSetter
}

func openPathRefreshSubscriber(ctx context.Context, remote UDPAddr, policy Policy,
	target pathSetter) (*pathRefreshSubscriber, error) {

	s := &pathRefreshSubscriber{
		target: target,
		policy: policy,
		remote: remote,
	}
	paths, err := pool.subscribe(ctx, remote.IA, s)
	if err != nil {
		return nil, nil
	}
	s.setFiltered(paths)
	return s, nil
}

func (s *pathRefreshSubscriber) Close() error {
	if s != nil {
		pool.unsubscribe(s.remote.IA, s)
	}
	return nil
}

func (s *pathRefreshSubscriber) setPolicy(policy Policy) {
	s.policy = policy
	s.setFiltered(pool.cachedPaths(s.remote.IA))
}

func (s *pathRefreshSubscriber) refresh(dst IA, paths []*Path) {
	s.setFiltered(paths)
}

func (s *pathRefreshSubscriber) setFiltered(paths []*Path) {
	if s.policy != nil {
		paths = s.policy.Filter(paths)
	}
	s.target.SetPaths(paths)
}

//////////////////// selector

// Selector controls the path used by a single **connected** socket. Stateful.
// The Path() function is invoked for every single packet.
type Selector interface {
	Path() *Path
	SetPaths([]*Path)
	OnPathDown(*Path, PathInterface)
}

type DefaultSelector struct {
	mutex              sync.Mutex
	paths              []*Path
	current            int
	currentFingerprint PathFingerprint
}

func (s *DefaultSelector) Path() *Path {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.paths) == 0 {
		return nil
	}
	return s.paths[s.current]
}

func (s *DefaultSelector) SetPaths(paths []*Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.paths = paths
	curr := 0
	if s.currentFingerprint != "" {
		for i, p := range s.paths {
			if p.Fingerprint == s.currentFingerprint {
				curr = i
				break
			}
		}
	}
	s.current = curr
	if len(s.paths) > 0 {
		s.currentFingerprint = s.paths[s.current].Fingerprint
	}
}

func (s *DefaultSelector) OnPathDown(path *Path, pi PathInterface) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if isInterfaceOnPath(s.paths[s.current], pi) || path.Fingerprint == s.currentFingerprint {
		// XXX: this is a quite dumb; will forget about the down notifications immediately.
		// XXX: this should be replaced with sending this to "Stats DB". Then the
		// selector needs to be subscribed to the stats DB.

		// Try next path. Note that this will keep cycling through all paths if none are working.
		s.current = (s.current + 1) % len(s.paths)
		fmt.Println("failover:", s.current, len(s.paths))
		s.currentFingerprint = s.paths[s.current].Fingerprint
	}
}
