// Copyright 2020 CrowdStrike Holdings, Inc.
//
// Use of this source code is governed by the MIT License.

package apbf_test

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/CrowdStrike/apbf"
)

const (
	testItemsCount = 10000000
)

var (
	testItems [][]byte
)

type newParams struct {
	k, l, g uint
}

type newWithRefreshParams struct {
	k, l, g uint
	r       time.Duration
}

type fpRate struct {
	k, l     uint
	expected float64
}

func init() {
	rand.Seed(time.Now().UnixNano())

	testItems = make([][]byte, testItemsCount)
	for i := range testItems {
		item := make([]byte, 8)
		rand.Read(item)
		testItems[i] = item
	}
}

func TestBasicAddQuery(t *testing.T) {
	params := []newParams{
		{1, 1, 1},
		{1, 1, 2},
		{1, 1, 100},
		{3, 1, 1},
		{3, 1, 2},
		{3, 1, 100},
		{1, 3, 1},
		{1, 3, 2},
		{1, 3, 100},
	}

	item1 := []byte("itemA")
	item2 := []byte("itemB")

	for _, p := range params {
		filter := p.New()

		if filter.Query(item1) {
			t.Errorf("Query returned true before item1 was added in filter %s", p)
		}

		filter.Add(item1)

		if !filter.Query(item1) {
			t.Errorf("Query returned false after item1 was added in filter %s", p)
		}

		if filter.Query(item2) {
			t.Errorf("Query returned true for item2 in filter %s", p)
		}
	}
}

func TestMaxCapacity(t *testing.T) {
	params := []newParams{
		{1, 1, 10},
		{1, 3, 10},
		{3, 1, 10},
		{3, 3, 10},
	}

	item1 := []byte("itemA")
	item2 := []byte("itemB")

	for _, p := range params {
		filter := p.New()

		// item1 is part of first generation
		filter.Add(item1)

		// adding both item1 and item2 should not result in false positives
		if filter.Query(item2) {
			t.Errorf("Query returned false positive in filter %s", p)
			continue
		}

		for i := 0; i < filter.MaxCapacity()-1; i++ {
			filter.Add(item2)
		}

		if !filter.Query(item1) {
			t.Errorf("Query returned false in filter %s", p)
		}

		filter.Add(item2)

		if filter.Query(item1) {
			t.Errorf("Query returned true in filter %s", p)
		}
	}
}

func TestRefresh(t *testing.T) {
	refresh := 50 * time.Millisecond
	params := []newWithRefreshParams{
		{3, 6, 10, refresh},
		{3, 8, 10, refresh},
	}

	item := []byte("itemA")

	for _, p := range params {
		filter := p.New()

		filter.Add(item)

		// a. wait one refresh interval will not evict the item
		<-time.After(refresh)

		if !filter.Query(item) {
			t.Errorf("Query returned false in filter %s", p)
		}

		// b. wait 2x number of generations times the refresh interval to ensure the item was evicted
		<-time.After(2 * time.Duration(filter.MaxGenerations()) * refresh)

		if filter.Query(item) {
			t.Errorf("Query returned true in filter %s", p)
		}
	}
}

func TestNextGeneration(t *testing.T) {
	params := []newParams{
		{1, 1, 10},
		{1, 3, 10},
		{3, 1, 10},
		{3, 3, 10},
	}

	item := []byte("itemA")

	for _, p := range params {
		filter := p.New()

		filter.Add(item)

		for i := 0; i < filter.MaxGenerations(); i++ {
			filter.NextGeneration()
		}

		if filter.Query(item) {
			t.Errorf("Query returned false in filter %s", p)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	params := []newParams{
		{4, 3, 10000},
		{10, 7, 10000},
		{18, 16, 10000},
	}

	for _, p := range params {
		filter := p.New()

		itemChan := make(chan []byte, filter.MaxGenerations())
		stopChan := make(chan struct{})
		var stopOnce sync.Once
		var wg sync.WaitGroup

		addGeneration := func(seed int) {
			defer wg.Done()

			for i := 0; i < int(p.g); i++ {
				item := getItem(seed + i)
				filter.Add(item)

				select {
				case itemChan <- item:
				case <-stopChan:
					return
				}
			}
		}

		queryGeneration := func() {
			defer wg.Done()

			for i := 0; i < int(p.g); i++ {
				select {
				case item := <-itemChan:
					if !filter.Query(item) {
						t.Errorf("Query returned false for item %s in filter %s", string(item), p)
						stopOnce.Do(func() { close(stopChan) })
					}
				case <-stopChan:
					return
				}
			}
		}

		for i := 0; i < filter.MaxGenerations(); i++ {
			wg.Add(2)

			go addGeneration(rand.Int())
			go queryGeneration()
		}

		wg.Wait()
	}
}

func TestEmptyItem(t *testing.T) {
	items := [][]byte{
		{},
		nil,
	}

	for i, item := range items {
		filter := apbf.New(3, 1, 10)

		filter.Add(item)

		if !filter.Query(item) {
			t.Errorf("Query returned false for item %d", i)
		}
	}
}

func TestCalculateFalsePositiveRate(t *testing.T) {
	epsilon := 1e-6
	items := []fpRate{
		{4, 3, 0.100586},
		{5, 7, 0.101603},
		{7, 5, 0.011232},
		{8, 8, 0.010244},
		{10, 7, 0.001211},
		{11, 9, 0.000918},
		{14, 11, 0.000099},
		{15, 15, 0.000100},
		{17, 13, 0.00001},
		{18, 16, 0.000009},
	}

	for _, f := range items {
		actual := apbf.CalculateFalsePositiveRate(f.k, f.l)

		if math.Abs(actual-f.expected) > epsilon {
			t.Errorf("Wrong FP rate for k=%d, k=%d: expected=%v vs. actual=%v", f.k, f.l, f.expected, actual)
		}
	}
}

func TestRealFalsePositiveRate(t *testing.T) {
	epochMax := 1000       // max number of epochs to converge
	epochThreshold := 5    // epoch required for FP confirmation
	capacity := uint(1000) // target filter capacity

	getParams := func(k, l uint) newParams {
		return newParams{k, l, capacity / (l + 1)}
	}

	params := []newParams{
		getParams(4, 3),
		getParams(5, 7),
		getParams(6, 14),
		getParams(7, 5),
		getParams(8, 8),
		getParams(9, 14),
		getParams(10, 7),
		getParams(11, 9),
		getParams(12, 14),
		getParams(14, 11),
		getParams(15, 15),
		getParams(16, 22),
		getParams(17, 13),
		getParams(18, 16),
		getParams(19, 22),
	}

	buff := make([]byte, 8)
	randItem := func(prefix byte) []byte {
		rand.Read(buff)
		buff[0] = prefix
		return buff
	}

	for _, p := range params {
		filter := p.New()
		expected := apbf.CalculateFalsePositiveRate(p.k, p.l)

		// a. fill the filter
		for i := 0; i < filter.MaxCapacity(); i++ {
			filter.Add(randItem(17))
		}

		// b. query for items that were not added
		epochSize := int(1 / expected)
		epochCount := 0
		count := 0
		fpCount := 0

		for epoch := 0; epoch < epochMax && epochCount < epochThreshold; epoch++ {
			for i := 0; i < epochSize; i++ {
				if filter.Query(randItem(19)) {
					fpCount++
				}
			}

			count += epochSize

			// c. compute real FP rate and compare
			actual := float64(fpCount) / float64(count)

			if actual <= expected {
				epochCount++
			} else {
				epochCount = 0
			}
		}

		if epochCount < epochThreshold {
			overall := float64(fpCount) / float64(count)
			t.Errorf("Filter %s did not converge to expected FP rate %v vs. %v", p, expected, overall)
		}
	}
}

func TestSnapshot(t *testing.T) {
	params := []newParams{
		{1, 1, 1},
		{1, 1, 2},
		{1, 1, 100},
		{3, 1, 1},
		{3, 1, 2},
		{3, 1, 100},
		{1, 3, 1},
		{1, 3, 2},
		{1, 3, 100},
	}

	item := []byte("itemA")

	for _, p := range params {
		filter1 := p.New()
		filter1.Add(item)

		snapshot := filter1.Snapshot()

		filter2 := apbf.NewFromSnapshot(snapshot)

		if !filter2.Query(item) {
			t.Errorf("Query returned false for filter %s", p)
		}
	}
}

func TestInvalidSnapshot(t *testing.T) {
	filter := apbf.NewWithRefresh(4, 3, 1000, time.Minute)
	valid := filter.Snapshot()

	invalid := []apbf.Snapshot{
		{},
		func(s apbf.Snapshot) apbf.Snapshot { s.K = 0; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.K = s.K - 1; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.K = s.K + 1; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.L = 0; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.L = s.L - 1; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.L = s.L + 1; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.G = 0; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.G = s.G - 1; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.G = s.G + 1; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.Base = 0; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.Base = s.K + s.L + 1; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.Count = s.G + 1; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.Buffer = nil; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.Buffer = []byte{}; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.Buffer = s.Buffer[:len(s.Buffer)-1]; return s }(valid),
		func(s apbf.Snapshot) apbf.Snapshot { s.Buffer = append(s.Buffer, 1); return s }(valid),
	}

	callNew := func(s apbf.Snapshot) (didPanic bool) {
		defer func() {
			didPanic = recover() != nil
		}()

		apbf.NewFromSnapshot(s)
		return
	}

	for i, s := range invalid {
		if !callNew(s) {
			t.Errorf("Unexpected result for snapshot at index %d", i)
		}
	}
}

func TestInvalidParams(t *testing.T) {
	invalid := []newWithRefreshParams{
		{},
		{0, 3, 100, 0},
		{3, 0, 100, 0},
		{3, 3, 0, 0},
		{3, 3, 100, -1},
	}

	callNew := func(p newWithRefreshParams) (didPanic bool) {
		defer func() {
			didPanic = recover() != nil
		}()

		p.New()
		return
	}

	for _, p := range invalid {
		if !callNew(p) {
			t.Errorf("Unexpected result for params %s", p)
		}
	}
}

func BenchmarkSmallFilterAdd(b *testing.B) {
	filter := apbf.New(3, 3, 1000)
	benchmarkAdd(b, filter)
}

func BenchmarkSmallFilterAddWithRefresh(b *testing.B) {
	filter := apbf.NewWithRefresh(3, 3, 1000, time.Minute)
	benchmarkAdd(b, filter)
}

func BenchmarkSmallFilterQuery(b *testing.B) {
	filter := apbf.New(3, 3, 1000)
	benchmarkQuery(b, filter)
}

func BenchmarkSmallFilterQueryWithRefresh(b *testing.B) {
	filter := apbf.NewWithRefresh(3, 3, 1000, time.Minute)
	benchmarkQuery(b, filter)
}

func BenchmarkLargeFilterAdd(b *testing.B) {
	filter := apbf.New(15, 15, 100000)
	benchmarkAdd(b, filter)
}

func BenchmarkLargeFilterAddWithRefresh(b *testing.B) {
	filter := apbf.NewWithRefresh(15, 15, 100000, time.Minute)
	benchmarkAdd(b, filter)
}

func BenchmarkLargeFilterQuery(b *testing.B) {
	filter := apbf.New(15, 15, 100000)
	benchmarkQuery(b, filter)
}

func BenchmarkLargeFilterQueryWithRefresh(b *testing.B) {
	filter := apbf.NewWithRefresh(15, 15, 100000, time.Minute)
	benchmarkQuery(b, filter)
}

func benchmarkAdd(b *testing.B, filter *apbf.Filter) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.Add(getItem(i))
	}
}

func benchmarkQuery(b *testing.B, filter *apbf.Filter) {
	// fill the filter
	for i := 0; i < filter.MaxCapacity(); i++ {
		filter.Add(getItem(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.Query(getItem(i))
	}
}

func (p newParams) New() *apbf.Filter {
	return apbf.New(p.k, p.l, p.g)
}

func (p newParams) String() string {
	return fmt.Sprintf("k=%d, l=%d, g=%d", p.k, p.l, p.g)
}

func (p newWithRefreshParams) New() *apbf.Filter {
	return apbf.NewWithRefresh(p.k, p.l, p.g, p.r)
}

func (p newWithRefreshParams) String() string {
	return fmt.Sprintf("k=%d, l=%d, g=%d, r=%s", p.k, p.l, p.g, p.r)
}

func getItem(i int) []byte {
	return testItems[i%testItemsCount]
}
