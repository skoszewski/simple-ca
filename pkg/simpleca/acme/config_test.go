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

package acme

import (
	"testing"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

func TestACMELimits(t *testing.T) {
	if got := Limits(simpleca.ACMEConfig{}); got.MaxAccounts != 1000 || got.MaxOrders != 50 || got.MaxNames != 100 ||
		got.MaxContacts != 10 || got.MaxNonces != 100000 {
		t.Errorf("default limits %+v", got)
	}
	got := Limits(simpleca.ACMEConfig{Days: 30, MaxAccounts: 5, MaxOrders: -1, MaxNames: 2, MaxContacts: 1, MaxNonces: 7})
	if got.Days != 30 || got.MaxAccounts != 5 || got.MaxOrders != 50 || got.MaxNames != 2 || got.MaxContacts != 1 ||
		got.MaxNonces != 7 {
		t.Errorf("limits set %+v, want them kept and the negative one the default", got)
	}
}
