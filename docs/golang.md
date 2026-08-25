# Go

The Go adapter uses the standard Go toolchain and a checked-in module lock.
The supported toolchain version is recorded in `.go-version`.

```sh
cd modules/golang
go mod download
make
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_GOLANG"
```
