package ntpmonitor

import (
	"math/rand"
)

// RandomChoice returns a random selection of n items from the slic s.
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
		i := rand.Intn(len(indices))

		result = append(result, s[indices[i]])
		if len(result) == n {
			break
		}

		indices = append(indices[:i], indices[i+1:]...)
	}

	return result
}
