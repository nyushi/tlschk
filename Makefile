COV_OUT=cover.out
SRC=*.go
TLSCHKR_DIR=cmd/tlschkr

$(TLSCHKR_DIR)/tlschkr: $(TLSCHKR_DIR)/*.go $(SRC)
	cd $(TLSCHKR_DIR) && go build && cd -

vet:
	go vet ./...

test: vet
	go test ./...

$(COV_OUT): $(SRC)
	go test -coverprofile=$(COV_OUT) .

test-cov: $(COV_OUT)
	go tool cover -func=$(COV_OUT)


test-cov-html: $(COV_OUT)
	go tool cover -html=$(COV_OUT)

clean:
	rm -rf $(TLSCHKR_DIR)/tlschkr

.PHONY: clean test test-cov test-cov-html vet
