// Copyright 2025 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { b64decode } from 'k6/encoding';

// base64 encoded output of 
// openssl ts -query -digest 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
const requestTsqB64 = "MEACAQEwMTANBglghkgBZQMEAgEFAAQgLPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQCCEXqSfGqwl1B";
const requestBody = b64decode(requestTsqB64);

// Custom metrics
const errorRate = new Rate('errors');
const latency = new Trend('latency', true);

// Test configuration
export const options = {
  scenarios: {
    load_test: {
      executor: 'ramping-vus',
      stages: [
        { duration: '15s', target: 1000 },
        { duration: '30s', target: 1000 },
        { duration: '15s', target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<1000'],
    errors: ['rate<0.001'],
  },
};

const baseUrl = (__ENV.TIMESTAMP_URL || 'http://localhost:3004').replace(/\/$/, '');
const timestampUrl = `${baseUrl}/api/v1/timestamp`;
const healthUrl = `${baseUrl}/ping`;

export default async function(data) {
  const startTime = Date.now();
  try {
    const response = http.post(
      timestampUrl,
      requestBody,
      { headers: { 'Content-Type': 'application/timestamp-query' } }
    );

    const duration = Date.now() - startTime;
    latency.add(duration);

    const success = check(response, { 'status is 201': (r) => r.status === 201 });
    errorRate.add(!success);

    if (!success) {
      console.log(`❌ Failed: ${response.status} ${response.body}`);
    } else if (response.status === 201) {
      console.log(`✅ Got timestamp in (${duration}ms)`);
    }

  } catch (e) {
    errorRate.add(1);
    console.log(`💥 Exception: ${e.message}`);
  }
  sleep(0.05);
}

export async function setup() {
  console.log(`🚀 Starting Timestamp Authority Load Test | Target: ${baseUrl}`);
  const health = http.get(healthUrl);
  if (health.status !== 200) throw new Error(`Health check failed`);
  console.log('✅ Health check passed');

  return {
    startTime: Date.now(),
  };
}

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`🏁 Test completed in ${duration.toFixed(1)}s`);
}
