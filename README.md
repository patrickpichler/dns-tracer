# dns-tracer

## How to run

The easiest way is to spawn a nix develop shell via
```sh
nix develop
```

And then run
```sh
make gen-bpf && go run -exec sudo ./main.go
```
