# Age-Partitioned Bloom Filters

Age-Partitioned Bloom Filters (APBF) is a novel approach for duplicate detection in sliding windows over an unbounded stream of items described in [Age-Partitioned Bloom Filters](https://arxiv.org/abs/2001.03147): Ariel Shtul, Carlos Baquero and Paulo Sérgio Almeida, 2020.

The implementation employs the enhanced double hashing technique for fast index computation introduced in [Bloom Filters in Probabilistic Verification](https://link.springer.com/chapter/10.1007/978-3-540-30494-4_26): Peter C. Dillinger and Panagiotis Manolios, 2004.

## Example

```golang
// create a filter with k=10, l=7, and g=1000
filter := apbf.New(10, 7, 1000)

item := []byte("test item")
filter.Add(item)

if filter.Query(item) {
    fmt.Println("item was found")
}
```

## Installation

Use `go get` to add the project to your workspace:
```bash
go get -u github.com/CrowdStrike/apbf
```

## Benchmarks

The following results show the performance of main filter operations `Add` and `Query` with and without refresh enabled for a small and large filter. Benchmarks were executed on a MacBook Pro 2017 dev laptop.

```
BenchmarkSmallFilterAdd-8                20000000       103 ns/op       0 B/op       0 allocs/op
BenchmarkSmallFilterAddWithRefresh-8     10000000       177 ns/op       0 B/op       0 allocs/op
BenchmarkSmallFilterQuery-8              10000000       133 ns/op       0 B/op       0 allocs/op
BenchmarkSmallFilterQueryWithRefresh-8   10000000       206 ns/op       0 B/op       0 allocs/op
BenchmarkLargeFilterAdd-8                 5000000       252 ns/op       0 B/op       0 allocs/op
BenchmarkLargeFilterAddWithRefresh-8      5000000       325 ns/op       0 B/op       0 allocs/op
BenchmarkLargeFilterQuery-8               3000000       431 ns/op       0 B/op       0 allocs/op
BenchmarkLargeFilterQueryWithRefresh-8    2000000       543 ns/op       0 B/op       0 allocs/op
```

## Contributors

[Bogdan-Ciprian Rusu](https://github.com/bcrusu) - Author/Maintainer

## License

The project is licensed under the [MIT License](LICENSE).
