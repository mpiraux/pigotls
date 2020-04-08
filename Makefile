all:
	git submodule init
	git submodule update
	cd picotls; \
	git submodule init; \
	git submodule update; \
	patch -p 1 -N < ../tls13_only.patch; \
	cmake ${CMAKE_OPTS} .; \
	make; \
	make check;
	CGO_LDFLAGS_ALLOW=\(.*picotls.*\)\|\(.*libssl.*\)\|\(.*libcrypto.*\) go build -n .
	CGO_LDFLAGS_ALLOW=\(.*picotls.*\)\|\(.*libssl.*\)\|\(.*libcrypto.*\) go build .
