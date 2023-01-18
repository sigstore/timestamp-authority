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
)

// RandomChoice returns a random selection of n items from the slice s.
// The choice is made using a PSEUDO RANDOM selection.
// If n is greater than len(s), an empty slice is returned.
func RandomChoice[T any](s []T, n int) []T {
	if n > len(s) || n < 1 {
		return []T{}
	}

	if n == len(s) {
		return s
	}

	var indices = make([]int, len(s))
	var result = make([]T, 0, n)
	for i := range s {
		indices[i] = i
	}

	for {
		// The use of deterministic (pseudo) random generators are
		// ok for this use-case.
		//nolint:gosec
		i := rand.Intn(len(indices))

		result = append(result, s[indices[i]])
		if len(result) == n {
			break
		}

		indices = append(indices[:i], indices[i+1:]...)
	}

	return result
}
