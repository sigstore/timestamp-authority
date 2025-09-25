# Timestamp Authority Load Test

`k6_load_test.js` is a [k6](https://k6.io) script for load testing a Timestamp
Authority service. The test sends a significant amount of requests to `/api/v1/timestamp`
and expects to receive a 201 response with a timestamp.

## Running the test

* Run a Timestamp Authority instance
* Configure the test scenario you want in test/loadtest/k6_load_test.js
* Install k6
* Run the test: `TIMESTAMP_URL=http://my.timestamp.url k6 run test/loadtest/k6_load_test.js`

## Running the test the easy way

`docker compose run --rm k6-loadtest`

This runs grafana/k6 container image and tests the timestamp-authority container image.

## Metrics and Thresholds

The test will fail if either of these conditions are met:
* The 95th percentile of request duration (`http_req_duration`) exceeds a limit
* The failure rate (`errors`) exceeds a set limit.

In addition an internal `latency` metric is measured.

These thresholds (and the default scenario configuration) are set to defaults where the
test comfortably passes `docker compose run --rm k6-loadtest` on a laptop: they should
be modified for load testing other setups.