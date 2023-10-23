// Based on:
// https://github.com/efficient/cuckoofilter/tree/master/src
// https://github.com/DylanMeeus/MediumCode/blob/master/cuckoofilter/main.go
// https://github.com/seiflotfy/cuckoofilter

package main

import (
	"crypto/sha1"
	"math"
)

// Define the types
type fingerprint []byte
type bucket []fingerprint

var hasher = sha1.New()

// Set default fingerprint size to 8 bits
// 8 bit fingerprint size equals to a false positive rate ~= 0.03
var b_size uint = 8

// Cuckoo Data structure based on https://www.pdl.cmu.edu/PDL-FTP/FS/cuckoo-conext2014.pdf
type Cuckoo struct {
	buckets []bucket
	m       uint // number of buckets
	b       uint // number of entries per bucket
	f       uint // fingerprint length in bits
	n       uint // number of items - filter capacity
}

// NewFilter creates a new cuckoo filter according to the parameters suggested by the authors
// "because it achieves the best or close-to-best space efficiency for the false positive
// rates that most practical applications 'A. Broder, M. Mitzenmacher, and A. Broder. Network
// Applications of Bloom Filters' may be interested in":
// n: number of items - filter capacity
// e: false positive rate (e.g., 0.01)
// returns a pointer to the cuckoo filter
func NewFilter(n uint, e float64) *Cuckoo {
	b := uint(4) // number of entries or fingerprints per bucket
	// following https://www.pdl.cmu.edu/PDL-FTP/FS/cuckoo-conext2014.pdf optimum recommendations
	f := fingerprintLength(b, e)
	// following https://www.pdl.cmu.edu/PDL-FTP/FS/cuckoo-conext2014.pdf
	// to calculate the number of buckets
	m := nextPower(n / f * b_size)

	// Set a minimum number of buckets
	if m == 0 {
		m = 1
	}

	// Make an array of buckets of len m
	buckets := make([]bucket, m)

	// Initialize the buckets
	for i := uint(0); i < m; i++ {
		buckets[i] = make(bucket, b) // make a bucket of len b
	}

	// return the created Cuckoo filter with the parameters
	return &Cuckoo{
		buckets: buckets,
		m:       m,
		b:       b,
		f:       f,
		n:       n,
	}

}

// fingerprintLength follows the formula f >= log2(2b/r) bits
// suggested by authors of https://www.pdl.cmu.edu/PDL-FTP/FS/cuckoo-conext2014.pdf
// e: target false positive rate
// b: number of entries per bucket
// Here:
//	- 8 bit fingerprint size equals to a false positive rate ~= 0.03
//	- 16 bit fingerprint size equals to a false positive rate ~= 0.0001

func fingerprintLength(b uint, e float64) uint {

	f := uint(math.Ceil(math.Log(2 * float64(b) / e)))
	f /= b_size // convert to x bit fingerprint. Default 8 bit fingerprint

	if f < 1 {
		f = 1
	}
	return f
}

func nextPower(i uint) uint {
	// It rounds up to the next highest power of 2
	// compute the next highest power of 2 of 32-bit
	// https://stackoverflow.com/questions/466204/rounding-up-to-next-power-of-2
	// https://graphics.stanford.edu/%7Eseander/bithacks.html#RoundUpPowerOf2

	// https://golang.org/ref/spec#Arithmetic_operators
	// https://golang.org/ref/spec#Operators_and_punctuation
	// i |= i >> n is a bitwise OR assignment operator
	// E.g.,
	//	i := 12  // i is 1100 in binary
	//	i |= i >> 2  // shifts 1100 to the right by 2 positions to get 0011,
	//	then original value 1100 is OR'd with 0011, resulting in 1111, which is 15 in decimal
	// 	and then assigns the result to i
	// We are using 1, 2, 4, 8, 16, and 32 as the shift values because we are using 64 bit integers

	// i-- is a post-decrement operator, meaning it decrements the value of i after using it in the expression
	i--
	i |= i >> 1
	i |= i >> 2
	i |= i >> 4
	i |= i >> 8
	i |= i >> 16
	i |= i >> 32
	// i++ is a post-increment operator, meaning it increments the value of i after using it in the expression
	i++
	return i
}

//

//func main() {
//}
