package shamirutil

import (
	"math/rand"
	"local/Ed25519Shamir/EdwardsShamir"
)

// RandomIndices initialises and returns a slice of n indices, each of which is
// random. Often it is desired that each index is distinct. This function does
// not gaurantee this, however the chance of two indices being equal is
// negligible for low n.
func Ed25519RandomIndices(n int) []EdwardsShamir.Scalar {
	indices := make([]EdwardsShamir.Scalar, n)
	for i := range indices {
		indices[i] = EdwardsShamir.RandomScalar()
	}
	return indices
}

// SequentialIndices initialises and returns a slice of n indices, where the
// slice index i is equal to i+1 in the field.
func Ed25519SequentialIndices(n int) []EdwardsShamir.Scalar {
	indices := make([]EdwardsShamir.Scalar, n)
	for i := range indices {
		indices[i].SetU16(uint16(i) + 1)
	}

	return indices
}

// Shuffle randomises the order of the givens shares in the slice.
func Ed25519Shuffle(shares EdwardsShamir.Shares) {
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})
}

// AddDuplicateIndex picks two random (distinct) indices in the given slice of
// shares and sets the share index of the second to be equal to that of the
// first.
func Ed25519AddDuplicateIndex(shares EdwardsShamir.Shares) {
	// Pick two distinct array indices.
	first, second := rand.Intn(len(shares)), rand.Intn(len(shares))
	for first == second {
		second = rand.Intn(len(shares))
	}

	// Set the second share to have the same index as the first.
	shares[second].Index = shares[first].Index
}

// SharesAreConsistent returns true if the given shares are found to be
// consistent. Consistency is defined as all points lying on some polynomial of
// degree less than `k`.
func Ed25519SharesAreConsistent(shares EdwardsShamir.Shares, k int) bool {
	if len(shares) < k {
		return true
	}

	secret := EdwardsShamir.Open(shares[:k])
	for i := 1; i <= len(shares)-k; i++ {
		recon := EdwardsShamir.Open(shares[i : i+k])
		if !recon.Eq(&secret) {
			return false
		}
	}

	return true
}