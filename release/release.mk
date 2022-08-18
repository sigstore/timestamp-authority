##################
# release section
##################

# used when releasing together with GCP CloudBuild
.PHONY: release
release:
	LDFLAGS="$(LDFLAGS)" goreleaser release --rm-dist --timeout 120m

# used when need to validate the goreleaser
.PHONY: snapshot
snapshot:
	LDFLAGS="$(LDFLAGS)" goreleaser release --skip-sign --skip-publish --snapshot --rm-dist --timeout 120m

###########################
# sign section
###########################

.PHONY: sign-container-release
sign-container-release: ko
	GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	./release/ko-sign-release-images.sh
