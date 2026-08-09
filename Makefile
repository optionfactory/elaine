REPO_OWNER=optionfactory
REPO_NAME=repospect

build:
	@cargo build

build-release:
	@cargo build --release --target x86_64-unknown-linux-musl

run:
	@cargo run

install:
	@sudo cp target/x86_64-unknown-linux-musl/release/repospect /usr/local/bin/repospect

clean:
	-@rm -rf target/
clean-cache:
	-@rm -rf cache/

check-deps:
	#cargo install cargo-edit
	@echo "checking for upgrades..."
	@echo ""
	@cargo upgrade --dry-run
	@echo ""
	@echo "checking for updates..."
	@echo ""
	@cargo update --dry-run


publish-github: build-release
	$(eval VERSION=v$(shell cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].version'))
	@cp target/x86_64-unknown-linux-musl/release/$(REPO_NAME) target/$(REPO_NAME)-linux-amd64-musl
	@cd target && sha256sum $(REPO_NAME)-linux-amd64-musl > SHA256SUMS
	@gh release create "$(VERSION)" \
		"target/$(REPO_NAME)-linux-amd64-musl" \
		"target/SHA256SUMS" \
		--repo "$(REPO_OWNER)/$(REPO_NAME)" \
		--title "$(VERSION)" \
		--target "master" \
		--notes ""
	-@rm target/$(REPO_NAME)-linux-amd64-musl SHA256SUMS
