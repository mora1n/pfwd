module github.com/mora1n/pfwd/guard

go 1.26.0

require github.com/cilium/ebpf v0.21.0

require golang.org/x/sys v0.37.0 // indirect

replace github.com/cilium/ebpf => /home/morain/go/pkg/mod/github.com/cilium/ebpf@v0.21.0

replace golang.org/x/sys => /home/morain/go/pkg/mod/golang.org/x/sys@v0.37.0
