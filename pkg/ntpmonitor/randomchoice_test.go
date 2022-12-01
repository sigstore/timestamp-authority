//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ntpmonitor

import (
	"math/rand"
	"testing"
)

var seed = int64(1668159633)

func TestEmptySelection(t *testing.T) {
	cases := []struct {
		input []string
		n     int
	}{
		{
			input: []string{},
			n:     -1,
		},
		{
			input: []string{},
			n:     0,
		},
		{
			input: []string{},
			n:     1,
		},
		{
			input: []string{"a", "b"},
			n:     -1,
		},
		{
			input: []string{"a", "b"},
			n:     0,
		},
		{
			input: []string{"a", "b"},
			n:     4,
		},
	}

	for _, c := range cases {
		got := RandomChoice(c.input, c.n)
		if len(got) != 0 {
			t.Fail()
		}
	}
}

func TestSelection(t *testing.T) {
	cases := []struct {
		input []string
		n     int
		want  []string
	}{
		{
			input: []string{"a"},
			n:     1,
			want:  []string{"a"},
		},
		{
			input: []string{"a", "b", "c", "d"},
			n:     1,
			want:  []string{"b"},
		},
		{
			input: []string{"a", "b", "c", "d", "e", "f", "g"},
			n:     3,
			want:  []string{"d", "e", "a"},
		},
	}

	// Math.rand is deterministic based on a given seed
	rand.Seed(seed)

	for _, c := range cases {
		got := RandomChoice(c.input, c.n)
		if len(got) != len(c.want) {
			t.Fail()
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("expected '%s' got '%s'",
					c.want[i],
					got[i])
			}
		}
	}
}
