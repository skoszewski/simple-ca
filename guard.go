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
	"sync"
	"time"
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

// authFailures are the refusals in a row of a client: their count, the last one, and the end of
// the hold.
type authFailures struct {
	count       int
	last, until time.Time
}

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

// attempt runs try for client unless it is held back, records its outcome, and returns its error.
func (g *authGuard) attempt(w http.ResponseWriter, client netip.Addr, try func() error) error {
	if err := g.check(w, client); err != nil {
		return err
	}
	err := try()
	g.record(client, err)
	return err
}

// check returns an error of status 429, setting Retry-After on w, while client is held back.
func (g *authGuard) check(w http.ResponseWriter, client netip.Addr) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	f := g.clients[guardKey(client)]
	if f == nil || !time.Now().Before(f.until) {
		return nil
	}
	wait := time.Until(f.until)
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
	return apiErr(http.StatusTooManyRequests, "too many refused attempts from %s; retry in %s", client,
		wait.Round(time.Second).String())
}

// record counts the outcome err of a request of client: a refused credential, of status 401, is
// counted, and a success, a nil err, forgets the refusals.
func (g *authGuard) record(client netip.Addr, err error) {
	var e *apiError
	refused := errors.As(err, &e) && e.status == http.StatusUnauthorized
	if err != nil && !refused {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	key, now := guardKey(client), time.Now()
	if !refused {
		delete(g.clients, key)
		return
	}
	for k, f := range g.clients {
		if now.Sub(f.last) > authForget {
			delete(g.clients, k)
		}
	}
	f := g.clients[key]
	if f == nil {
		f = &authFailures{}
		g.clients[key] = f
	}
	f.count, f.last = f.count+1, now
	if n := f.count - authFreeFailures; n > 0 {
		f.until = now.Add(min(authFirstWait<<min(n-1, 20), authMaxWait))
	}
}
