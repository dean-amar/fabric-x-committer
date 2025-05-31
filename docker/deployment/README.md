<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->
# docker-compose based test deployment

This docker-compose based deployment allows to start and use a simple Committer deployment.
See [compose.yaml](compose.yaml) for the deployment details.

```bash
docker-compose up
```

In the `loadgen` folder you find another compose file to run the workload generator.
```bash
cd loadgen
docker-compose up
```

Check the grafana dashboard to see the performance metrics [http://localhost:3000](http://localhost:3000).

By default, the workload generator sets a throughput limit to 1000 TPS. Use the following command to change the limit.
```bash
curl -X POST http://localhost:6997/setLimits -H 'Content-Type: application/json' -d '{"limit": 100}'
```
