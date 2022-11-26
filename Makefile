VERSION=v0.0.1

bin: clean smail

.PHONY: smail
smail: bin/smail_darwin bin/smail_linux

bin/smail_darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/smail_darwin cmd/smail/*.go
	openssl sha512 bin/smail_darwin > bin/smail_darwin.sha512

bin/smail_linux:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/smail_linux cmd/smail/*.go
	openssl sha512 bin/smail_linux > bin/smail_linux.sha512

bin/smail_hostarch:
	mkdir -p bin
	go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/smail_hostarch cmd/smail/*.go
	openssl sha512 bin/smail_hostarch > bin/smail_hostarch.sha512


.PHONY: clean
clean:
	rm -rf bin