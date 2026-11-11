// MIT License
//
// Copyright (c) 2026 Slawomir Koszewski
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"errors"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

// ---- throttling of refused credentials --------------------------------------

// authFreeFailures is the number of refusals in a row a client has before it is held back.
var authFreeFailures = 5

const (
	// authFirstWait is the first hold of a client, doubled by each further refusal.
	authFirstWait = time.Second
	// authMaxWait is the longest hold of a client.
	authMaxWait = 15 * time.Minute
	// authForget is how long the refusals of a client are kept after the last one.
	authForget = time.Hour
)

// guard holds back the clients whose credentials serve refuses, on every route checking them.
var guard = newAuthGuard()

// authGuard holds back the clients whose tokens, setup codes or ID tokens are refused too often
// in a row, an IPv6 client by its /64.
type authGuard struct {
	mu      sync.Mutex
	clients map[netip.Prefix]*authFailures
}

// authFailures are the refusals in a row of a client: their count with the attempts under way,
// those attempts, the last refusal, and the end of the hold.
type authFailures struct {
	count, pending int
	last, until    time.Time
}

// errUncounted is the outcome of an attempt that is neither a refusal nor a success.
var errUncounted = errors.New("uncounted attempt")

// newAuthGuard returns a guard without refusals.
func newAuthGuard() *authGuard {
	return &authGuard{clients: map[netip.Prefix]*authFailures{}}
}

// guardKey returns the prefix a client is counted by.
func guardKey(client netip.Addr) netip.Prefix {
	bits := 32
	if client.Is6() {
		bits = 64
	}
	prefix, _ := client.Prefix(bits)
	return prefix
}

// attempt runs try for the client of r unless it is held back, records its outcome, audits a
// refusal and a hold for the CA in dir, and returns its error, nil for errUncounted.
func (g *authGuard) attempt(w http.ResponseWriter, r *http.Request, dir string, try func() error) error {
	client := clientAddr(r)
	if err := g.check(w, client); err != nil {
		return err
	}
	err := try()
	hold := g.record(client, err)
	if errors.Is(err, errUncounted) {
		return nil
	}
	var e *apiError
	if errors.As(err, &e) && e.status == http.StatusUnauthorized {
		auditRefused(r, dir, e.msg, client)
		if hold > 0 {
			simpleca.Audit(dir, "auth.held", "client", client.String(), "wait", hold.String())
		}
	}
	return err
}

// auditRefused audits the refusal of a credential, or of a request without one, to the client of
// r for the CA in dir, with the reason.
func auditRefused(r *http.Request, dir, reason string, client netip.Addr) {
	route, _, _ := strings.Cut(r.RequestURI, "?")
	simpleca.Audit(dir, "auth.refused", "route", route, "reason", reason, "client", client.String())
}

// check counts an attempt of client, or returns an error of status 429, setting Retry-After on w,
// while client is held back, or has an attempt under way after its free refusals.
func (g *authGuard) check(w http.ResponseWriter, client netip.Addr) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	key, now := guardKey(client), time.Now()
	for k, f := range g.clients {
		if f.pending == 0 && now.Sub(f.last) > authForget {
			delete(g.clients, k)
		}
	}
	f := g.clients[key]
	if f == nil {
		f = &authFailures{last: now}
		g.clients[key] = f
	}
	wait := f.until.Sub(now)
	if wait <= 0 && f.pending > 0 && f.count >= authFreeFailures {
		wait = authFirstWait
	}
	if wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		return apiErr(http.StatusTooManyRequests, "too many refused attempts from %s; retry in %s", client,
			wait.Round(time.Second).String())
	}
	f.count, f.pending = f.count+1, f.pending+1
	return nil
}

// record settles the attempt of client that check counted with its outcome err: a refused
// credential, of status 401, stays counted, a success, a nil err, forgets the refusals, and another
// error takes the attempt back. It returns the hold the refusal starts, zero for none.
func (g *authGuard) record(client netip.Addr, err error) time.Duration {
	var e *apiError
	refused := errors.As(err, &e) && e.status == http.StatusUnauthorized
	g.mu.Lock()
	defer g.mu.Unlock()
	key, now := guardKey(client), time.Now()
	f := g.clients[key]
	if f == nil {
		return 0
	}
	f.pending--
	switch {
	case err == nil:
		f.count = f.pending
	case !refused:
		f.count--
	}
	if !refused {
		if f.count <= 0 && f.pending <= 0 {
			delete(g.clients, key)
		}
		return 0
	}
	f.last = now
	n := f.count - authFreeFailures
	if n <= 0 {
		return 0
	}
	hold := min(authFirstWait<<min(n-1, 20), authMaxWait)
	f.until = now.Add(hold)
	return hold
}
