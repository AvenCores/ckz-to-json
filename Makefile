APP     := ckz2json
VERSION ?= 1.0.0
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 windows_arm64

.PHONY: all test vet release build run clean

all: release

test:
	go test ./...

vet:
	go vet ./...

# Local build for the current platform
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP) ./cmd/$(APP)

run: build
	./dist/$(APP)

# Cross-compile for linux/darwin/windows on amd64/arm64
release: vet test
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
	  os=$${p%_*}; arch=$${p#*_}; ext=""; \
	  [ $$os = windows ] && ext=.exe; \
	  name=$(APP)-$$os-$$arch; \
	  echo "==> $$name"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	    go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$name$$ext ./cmd/$(APP) || exit 1; \
	done

clean:
	rm -rf dist
