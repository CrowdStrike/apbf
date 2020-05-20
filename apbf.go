// Copyright 2020 CrowdStrike Holdings, Inc.
//
// Use of this source code is governed by the MIT License.

package apbf

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spaolacci/murmur3"
)

//go:generate protoc --gogo_out=. snapshot.proto

// Filter represents the Age-Partitioned Bloom Filter (APBF).
// The implementation is safe for concurrent use.
type Filter struct {
	k           uint
	l           uint
	h           uint         // slice count
	g           uint         // generation size
	r           int64        // refresh interval in nano
	m           uint         // slice bit count
	lock        sync.RWMutex // guards all below
	base        uint         // current slice 1-based index
	buffer      []byte       // circular buffer
	count       uint         // current generation count
	lastRefresh int64
	hasherPool  *sync.Pool
}

type hash [2]uint

// New returns the APBF with k + l slices and g generation size.
func New(k, l, g uint) *Filter {
	return new(k, l, g, 0)
}

// NewWithRefresh returns the APBF with k + l slices, g generation size, and r refresh interval.
func NewWithRefresh(k, l, g uint, r time.Duration) *Filter {
	return new(k, l, g, r)
}

func new(k, l, g uint, r time.Duration) *Filter {
	if k == 0 || l == 0 || g == 0 || r < 0 {
		panic("invalid parameters")
	}

	h, m, bufferLen := deriveParams(k, l, g)

	return &Filter{
		k:           k,
		l:           l,
		h:           h,
		g:           g,
		r:           int64(r),
		m:           m,
		base:        1,
		buffer:      make([]byte, bufferLen),
		count:       0,
		hasherPool:  getHasherPool(),
		lastRefresh: time.Now().UnixNano(),
	}
}

// NewFromSnapshot recreates the matching filter from the provided snapshot.
func NewFromSnapshot(s Snapshot) *Filter {
	if s.K == 0 || s.L == 0 || s.G == 0 || s.R < 0 {
		panic("invalid snapshot")
	}

	h, m, bufferLen := deriveParams(uint(s.K), uint(s.L), uint(s.G))

	validBuffer := len(s.Buffer) == bufferLen
	validBase := uint(s.Base) >= 1 && uint(s.Base) <= h
	validCount := s.Count <= s.G

	if !validBuffer || !validBase || !validCount {
		panic("invalid snapshot")
	}

	return &Filter{
		k:           uint(s.K),
		l:           uint(s.L),
		h:           h,
		g:           uint(s.G),
		r:           int64(s.R),
		m:           m,
		base:        uint(s.Base),
		buffer:      cloneSlice(s.Buffer),
		count:       uint(s.Count),
		hasherPool:  getHasherPool(),
		lastRefresh: time.Now().UnixNano(),
	}
}

func deriveParams(k, l, g uint) (uint, uint, int) {
	h := k + l                                  // slice count
	n := k * g                                  // slice capacity
	m := uint(math.Ceil(1.442695 * float64(n))) // slice bit count
	mt := h * m                                 // total bit count
	bufferLen := int((mt + 7) / 8)

	return h, m, bufferLen
}

// Add item to the set.
func (f *Filter) Add(item []byte) {
	f.refresh()
	hash := f.getHash(item)

	f.lock.Lock()

	if f.count == f.g {
		f.shift()
	}

	slice := f.base
	for i := uint(0); i < f.k; i++ {
		bit := f.location(slice, hash)
		f.setBit(bit)

		slice = f.nextSlice(slice)
	}

	f.count++
	f.lock.Unlock()
}

// Query returns true if the item is in the set and false otherwise. A true value might be a false positive whereas false is always correct.
func (f *Filter) Query(item []byte) bool {
	f.refresh()
	hash := f.getHash(item)

	f.lock.RLock()
	slice := f.base
	matched := uint(0)

	for i := f.h; i >= f.k-matched; i-- {
		bit := f.location(slice, hash)

		if f.hasBit(bit) {
			matched++
			if matched == f.k {
				break
			}
		} else {
			matched = 0
		}

		slice = f.nextSlice(slice)
	}

	f.lock.RUnlock()
	return matched == f.k
}

// NextGeneration transitions to next generation.
func (f *Filter) NextGeneration() {
	f.lock.Lock()
	f.shift()
	f.lock.Unlock()
}

// Snapshot returns a consistent snapshot of filter state.
func (f *Filter) Snapshot() Snapshot {
	f.lock.RLock()

	result := Snapshot{
		K:      uint64(f.k),
		L:      uint64(f.l),
		G:      uint64(f.g),
		R:      uint64(f.r),
		Base:   uint64(f.base),
		Count:  uint64(f.count),
		Buffer: cloneSlice(f.buffer),
	}

	f.lock.RUnlock()
	return result
}

// MaxCapacity returns filter max capacity.
func (f *Filter) MaxCapacity() int {
	return int(f.g) * f.MaxGenerations()
}

// MaxGenerations returns filter max generations count.
func (f *Filter) MaxGenerations() int {
	return int(f.l + 1)
}

func (f *Filter) refresh() {
	if f.r == 0 {
		return
	}

	now := time.Now().UnixNano()

	// fast path
	lastRefresh := atomic.LoadInt64(&f.lastRefresh)
	if lastRefresh+f.r > now {
		return
	}

	// slow path
	f.lock.Lock()
	for {
		next := f.lastRefresh + f.r
		if next > now {
			break
		}

		f.shift()
		f.lastRefresh = next
	}

	f.lock.Unlock()
}

func (f *Filter) shift() {
	f.count = 0
	f.base = f.prevSlice(f.base)

	bit := (f.base - 1) * f.m
	endBit := bit + f.m

	for bit < endBit && bit%8 != 0 {
		f.clearBit(bit)
		bit++
	}

	for bit < endBit && bit+8 < endBit {
		f.buffer[bit/8] = 0
		bit += 8
	}

	for bit < endBit {
		f.clearBit(bit)
		bit++
	}
}

func (f *Filter) getHash(item []byte) hash {
	hasher := f.hasherPool.Get().(murmur3.Hash128)
	hasher.Reset()
	hasher.Write(item)

	h1, h2 := hasher.Sum128()

	f.hasherPool.Put(hasher)
	return hash{uint(h1), uint(h2)}
}

func (f *Filter) location(i uint, h hash) uint {
	t := (i*i*i - i) / 6
	return (i-1)*f.m + (h[0]+i*h[1]+t)%f.m // enhanced double hashing
}

func (f *Filter) nextSlice(i uint) uint {
	if i == f.h {
		return 1
	}

	return i + 1
}

func (f *Filter) prevSlice(i uint) uint {
	if i == 1 {
		return f.h
	}

	return i - 1
}

func (f *Filter) setBit(index uint) {
	f.buffer[index/8] |= 1 << (index % 8)
}

func (f *Filter) clearBit(index uint) {
	f.buffer[index/8] &^= 1 << (index % 8)
}

func (f *Filter) hasBit(index uint) bool {
	return f.buffer[index/8]&(1<<(index%8)) != 0
}

// CalculateFalsePositiveRate computes the false positive rate for given k and l parameters.
func CalculateFalsePositiveRate(k, l uint) float64 {
	if k == 0 || l == 0 {
		panic("invalid parameters")
	}

	type key struct {
		a, i uint
	}

	cache := map[key]float64{}

	var calculate func(a, i uint) float64
	calculate = func(a, i uint) float64 {
		if a == k {
			return 1
		} else if i > l+a {
			return 0
		}

		ck := key{a, i}
		if val, ok := cache[ck]; ok {
			return val
		}

		ri := 0.5
		if i < k {
			ri = float64(i+1) / float64(2*k)
		}

		val := ri*calculate(a+1, i+1) + (1-ri)*calculate(0, i+1)
		cache[ck] = val
		return val
	}

	return calculate(0, 0)
}

func cloneSlice(src []byte) []byte {
	dest := make([]byte, len(src))
	copy(dest, src)
	return dest
}

func getHasherPool() *sync.Pool {
	return &sync.Pool{
		New: func() interface{} { return murmur3.New128() },
	}
}
