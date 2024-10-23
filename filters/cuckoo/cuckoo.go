// Based on:
// https://github.com/efficient/cuckoofilter/tree/master/src
// https://github.com/DylanMeeus/MediumCode/blob/master/cuckoofilter/main.go
// https://github.com/seiflotfy/cuckoofilter

package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
)

// Define the types
type fingerprint []byte
type bucket []fingerprint

var hasher = sha1.New()

// how many times do we try to move items around during insertion
const retries = 500

// Set default fingerprint size to 8 bits
// 8 bit fingerprint size equals to a false positive rate ~= 0.03
var b_size uint = 8

// Another option is b_size=4, f=16 bit,
//which correspond to a false positive rate of r ~= 0.0001

// Set default filter capacity of entries to 4
// based on the paper https://www.pdl.cmu.edu/PDL-FTP/FS/cuckoo-conext2014.pdf
var b uint = 4 // number of entries or fingerprints per bucket

// Cuckoo Data structure based on https://www.pdl.cmu.edu/PDL-FTP/FS/cuckoo-conext2014.pdf
type Cuckoo struct {
	buckets []bucket
	m       uint // number of buckets
	b       uint // number of entries per bucket in bits
	f       uint // fingerprint length in bits
	n       uint // number of items - filter capacity
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

// NewCuckooFilter creates a new cuckoo filter according to the parameters suggested by the authors
// "because it achieves the best or close-to-best space efficiency for the false positive
// rates that most practical applications 'A. Broder, M. Mitzenmacher, and A. Broder. Network
// Applications of Bloom Filters' may be interested in":
// n: number of items - filter capacity
// e: false positive rate (e.g., 0.01)
// returns a pointer to the cuckoo filter
func NewCuckooFilter(n uint, e float64) *Cuckoo {
	//b := uint(4) // number of entries or fingerprints per bucket
	// following https://www.pdl.cmu.edu/PDL-FTP/FS/cuckoo-conext2014.pdf optimum recommendations
	f := fingerprintLength(b, e)
	// following https://www.pdl.cmu.edu/PDL-FTP/FS/cuckoo-conext2014.pdf
	// to calculate the number of buckets
	m := nextPower(n / f * b_size)

	// Set a minimum number of buckets
	// to at least 1 bucket
	if m == 0 {
		m = 1
	}

	// Make an array of buckets of len m
	// if m = 4, then buckets = [bucket, bucket, bucket, bucket]
	buckets := make([]bucket, m)

	// Initialize each bucket within the array of buckets
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

// The hashes function would have the inputs:
// - c *Cuckoo: the cuckoo filter to insert the item using a pointer to the cuckoo filter struct
// other options would be to pass the cuckoo filter struct by value (c Cuckoo) or by reference (c &Cuckoo)
// but we don't want to copy the struct every time we call the function and it is more efficient to pass
// a pointer to the struct allowing to modify the struct while the other options would pass a copy of the struct
// the function hashes returns h1, h2 and the fingerprint
func (c *Cuckoo) hashes(data string) (uint, uint, fingerprint) {
	// Compute the hash of the data string input
	h := hash([]byte(data))

	// Get the fingerprint of the hash of the data string
	// using the f value set in the cuckoo filter struct for the fingerprint length in bits
	// by slicing the hash from 0 to f
	f := h[0:c.f]

	// Convert a portion of the first hash value to an unsigned integer using BigEndian
	i1 := uint(binary.BigEndian.Uint32(h))

	// XOR (the ^ operator) the first hash value with the second hash value
	// which returns a bit set to 1 for each position
	//where the corresponding bits of the operands are different.
	// E.g. 1010 ^ 1100 = 0110
	// This is used to generate a second hash value different from the first hash value
	i2 := i1 ^ uint(binary.BigEndian.Uint32(hash(f)))

	// i1 and 12 represent the two possible buckets for the item
	// while f represents the fingerprint of the item to insert, which is a slice of the hash of the item
	return i1, i2, fingerprint(f)
}

func hash(data []byte) []byte {
	// Compute the fingerprint of the item
	hasher.Write([]byte(data))

	// Get the SHA1 hash
	hash := hasher.Sum(nil)

	// Reset the hasher for the next use
	hasher.Reset()

	return hash
}

// nextIndex returns the next index for entry, or an error if the bucket is full
func (b bucket) nextIndex() (int, error) {
	for i, f := range b {
		if f == nil {
			return i, nil
		}
	}
	return -1, errors.New("bucket full")
}

// Insert adds an item to the cuckoo filter
//  1. Compute the fingerprint of the item
//  2. Compute the two possible buckets for the item
//  3. Try to insert the item in the first bucket
//  4. If the first bucket is full, try to insert the item in the second bucket
//  5. If the second bucket is full, pick a random entry from the second bucket
//     and try to insert it in the first bucket
//
// Here is the pseudocode from the paper:
// try to store in bucket 1
// if success-> done
// if not -> try to store in bucket 2
// if success -> done
// if not ->
//
//	while retry < retryLimit
//	    pick random entry (r) from bucket 1
//	    move entry (r) to alternate location
//	    try store in new bucket
//	    if success -> done
//
// The input is a string corresponding to the item to insert in the cuckoo filter
func (c *Cuckoo) insert(input string) {

	// Get the two possible buckets (i1, i2) for the item and the fingerprint (f) to insert
	// i1 and i2 only indicate the bucket index in the array of buckets for two possible buckets
	i1, i2, f := c.hashes(input)

	// first try bucket one to find an empty slot by calling the nextIndex function
	// pick a bucket from the array of buckets using the modulo operator with l1
	// b1 is a bucket of type []fingerprint
	b1 := c.buckets[i1%c.m]

	// Get i and err from the nextIndex function ("i, err := b1.nextIndex();")
	// validating that there is an empty slot in the bucket ("err == nil")
	// by checking if the error is nil
	if i, err := b1.nextIndex(); err == nil {
		// if there is an empty slot, insert the fingerprint
		b1[i] = f
		// No return value here because we are modifiying the "buckets"
		// within the Cuckoo struct
		return
	}

	// then try bucket two to find an empty slot if bucket one is full
	b2 := c.buckets[i2%c.m]
	if i, err := b2.nextIndex(); err == nil {
		b2[i] = f

		// No return value here because we are modifiying the "buckets"
		//within the Cuckoo struct
		return
	}

	// else we need to start relocating/shuffling items
	i := i1

	// Using the retries constant, try to relocate/shuffle items around to make space
	//for a maximum of retries times
	for r := 0; r < retries; r++ {
		index := i % c.m
		entryIndex := rand.Intn(int(c.b))
		// swap
		f, c.buckets[index][entryIndex] = c.buckets[index][entryIndex], f
		i = i ^ uint(binary.BigEndian.Uint32(hash(f)))
		b := c.buckets[i%c.m]
		if idx, err := b.nextIndex(); err == nil {
			b[idx] = f
			return
		}
	}
	panic("cuckoo filter full")
}

func (b bucket) contains(f fingerprint) (int, bool) {
	for i, x := range b {
		if bytes.Equal(x, f) {
			return i, true
		}
	}
	return -1, false
}

// lookup needle in the cuckoo filter
func (c *Cuckoo) lookup(needle string) bool {

	// Get the two possible buckets (i1, i2) for the item and the fingerprint (f) to lookup
	i1, i2, f := c.hashes(needle)

	// Check if the fingerprint is in the first bucket
	_, b1 := c.buckets[i1%c.m].contains(f)

	// Check if the fingerprint is in the second bucket
	_, b2 := c.buckets[i2%c.m].contains(f)

	// Return true if the fingerprint is in either bucket
	return b1 || b2
}

// delete the fingerprint from the cuckoo filter
func (c *Cuckoo) delete(needle string) {

	// Get the two possible buckets (i1, i2) for the item and the fingerprint (f) to delete
	i1, i2, f := c.hashes(needle)

	// try to remove from bucket 1
	b1 := c.buckets[i1%c.m]

	// if the fingerprint is in the first bucket, set it to nil
	if ind, ok := b1.contains(f); ok {
		b1[ind] = nil
		return
	}

	// try to remove from bucket 2
	b2 := c.buckets[i2%c.m]

	// if the fingerprint is in the second bucket, set it to nil
	if ind, ok := b2.contains(f); ok {
		b2[ind] = nil
		return
	}
}

func main() {
	// Generate a new cuckoo filter with 10 items and a false positive rate of 0.1
	cf := NewCuckooFilter(10, 0.1)

	// Insert the "hello" item in the cuckoo filter
	cf.insert("hello")

	// Insert the "world" item in the cuckoo filter
	cf.insert("world")

	// Validate if the "hello" item is in the cuckoo filter
	r := cf.lookup("hello")
	fmt.Printf("hello: %v\n", r)

	// Validate if the "world" item is in the cuckoo filter
	r = cf.lookup("world")
	fmt.Printf("world: %v\n", r)

	// Delete the "world" item from the cuckoo filter
	cf.delete("world")

	// Validate if the "world" item is in the cuckoo filter
	r = cf.lookup("world")
	fmt.Printf("world: %v\n", r)
}
