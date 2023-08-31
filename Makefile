all:
	go build -ldflags "-s -w"  -o hfp *.go

debug:
	go build -o hfp *.go

.PHONY: clean
clean:
	rm -fr hfp
