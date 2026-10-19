# Releasing timestamp authority server and client

## Publishing updated binaries and container

This guide assumes that `upstream` references github.com/sigstore/timestamp-authority.

Create and push a new tag. Note that you can't create a tag without creating a release in the GitHub UI, so you'll need to do this locally.

```
git pull upstream main
export RELEASE_TAG=v1.2.3 # Specify version
git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}"
git push upstream ${RELEASE_TAG}
```

After the tag is pushed, two workflows will kick off:

* [cut-release](https://github.com/sigstore/timestamp-authority/actions/workflows/release.yaml)
* [Create and publish Docker image](https://github.com/sigstore/timestamp-authority/actions/workflows/build_container.yml)

Once "cut-release" finishes, go to [Releases](https://github.com/sigstore/timestamp-authority/releases), select
the latest draft release, add release notes, and publish it.

## Updating the infrastructure

Update the [Helm chart](https://github.com/sigstore/helm-charts/tree/main/charts/tsa) to the latest version.
Follow [this example](https://github.com/sigstore/helm-charts/pull/1148).

Get the container digest:

```
crane digest ghcr.io/sigstore/timestamp-server:v1.2.3 # Specify version
```

Update `charts/tsa/values.yaml` with the new container version and digest.

Update `charts/tsa/Chart.yaml`, bumping `version`, `appVersion`, and the image reference.

Run `helm-docs -g charts/tsa` to update the README.

Create a PR and wait for an oncall engineer to approve and merge.

Afterwards, update the [scaffold](https://github.com/sigstore/helm-charts/tree/main/charts/scaffold)
chart with the bumped TSA chart version.

An oncall engineer also needs to update the scaffold chart version on the PGI repo.
