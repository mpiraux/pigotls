.ONESHELL:
all:
	git submodule init
	git submodule update
	cd picotls
	git submodule init
	git submodule update
	cmake .
	make
	make check
	cd ..
	CGO_LDFLAGS_ALLOW=.*picotls.* go build pigotls.go