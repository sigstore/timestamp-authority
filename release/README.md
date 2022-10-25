# Release

This directory contain the files and scripts to run a timestamp release.

# Cutting a timestamp Release

1. Release notes: Create a PR to update and review release notes in CHANGELOG.md.
  - Check merged pull requests since the last release and make sure enhancements, bug fixes, and authors are reflected in the notes.

You can get a list of pull requests since the last release by substituting in the date of the last release and running:

```
git log --pretty="* %s" --after="YYYY-MM-DD"
```

and a list of authors by running:

```
git log --pretty="* %an" --after="YYYY-MM-DD" | sort -u
```

1. Tag the repository

```shell
$ export RELEASE_TAG=<release version, eg "v1.1.0">
$ git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}"
$ git push upstream ${RELEASE_TAG}
```

Note that `upstream` should be the upstream Sigstore repository. You may have to change this if you've configured remotes.

1. This will trigger a GitHub Workflow that will build the binaries and the images.

1. Go to [releases](https://github.com/sigstore/timestamp-authority/releases) and edit the draft release.
   The tag should be selected automatically. Edit the release notes, copying in the changelog.
   Click "Publish Release".

1. Send an announcement email to `sigstore-dev@googlegroups.com` mailing list

1. Post on the `#general` Slack channel
