<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->
# Performance Tuning Guide

This guide explains how each configuration parameter affects system performance — throughput, latency, memory, and pipeline flow. All parameters are documented with their sample values in `cmd/config/samples/`.

## Table of Contents

1. [Pipeline Flow Control](#1-pipeline-flow-control)
2. [Identifying the Bottleneck](#2-identifying-the-bottleneck)
3. [Sidecar](#3-sidecar)
4. [Coordinator](#4-coordinator)
5. [Verifier](#5-verifier)
6. [Validator-Committer (VC)](#6-validator-committer-vc)
7. [Query Service](#7-query-service)
8. [Snapshot Hasher](#8-snapshot-hasher)
9. [Database](#9-database)
10. [Co-location Impact](#10-co-location-impact)
11. [A Starting Point for Large Deployments](#11-a-starting-point-for-large-deployments)
12. [Benchmarking](#12-benchmarking)

## 1. Pipeline Flow Control

The commit pipeline processes transactions through a sequence of stages connected by bounded channels and slot-based limits. These flow controls don't just protect memory — they directly control how much work flows through the pipeline.

```
Orderer → Sidecar → Coordinator → Dependency Graph → Verifier → VC → Database
             ↑            ↑                                      |
             └── status ──└──────────── status ──────────────────┘
```

Each `→` is a bounded channel or gRPC stream. The system uses three types of flow control:

- **Slot-based limits** act as per-transaction semaphores. Slots are acquired before processing and released only when transactions complete downstream. When exhausted, channels fill up and the Sidecar stops pulling blocks.
- **Channel buffers** connect adjacent stages within a process. When full, the producer blocks.
- **gRPC flow control** operates at the transport layer between services. gRPC uses HTTP/2 flow control windows — when a receiver is slow, its window fills up and the sender is blocked from writing more data. This prevents a fast producer (e.g., Sidecar) from overwhelming a slow consumer (e.g., Coordinator) at the network level, independent of the application-level slot and channel limits.

The windows are configurable per client and per server, under `flow-control` in a client section (including the sidecar's and load generator's `orderer` section) or in the `server` section: `initial-window-size` (per stream, default 16 MB) and `initial-conn-window-size` (per connection, shared by its streams, default 32 MB). They must be sized on both ends of a link, because the window a peer may write into is the one this side advertises — raising it on one side alone achieves nothing. Zero restores gRPC's own BDP-based tuning, which any explicit value disables. The defaults apply to configurations loaded from YAML. These are credit limits rather than allocations, so the cost is bounded buffering per connection, and only under overload.

Windows that are too small do not show up in the queue metrics below: every queue reads zero while the pipeline sits well under capacity, because the senders are blocked inside the transport rather than waiting on a channel. The signature is a goroutine dump with sender goroutines parked in `transport.(*writeQuota).get`, alongside receiving services running far below their CPU capacity. With gRPC's own defaults on a nineteen-machine deployment, every one of the coordinator's senders to the verifiers was blocked there while the verifiers ran 22 of 64 cores; sizing the windows took the pipeline from 510,371 to 578,383 tps and cut its latency at a sustainable 500,000 tps from 645 ms to 392 ms.

Setting any limit too low starves the pipeline — stages run in lock-step rather than streaming, and throughput drops. Setting limits too high increases memory usage and queuing latency. The goal is finding the balance where the pipeline has enough in-flight work to sustain throughput without excessive queuing.

## 2. Identifying the Bottleneck

Monitor queue length gauges to find the bottleneck. A growing queue means the downstream stage cannot keep up. Tune that stage first. The full list of queue metrics and other observability metrics can be found in the [Metrics Reference](metrics_reference.md). Key queues to watch:

| Queue Metric | Stage | Growing Queue Means |
|-------------|-------|---------------------|
| `sidecar_relay_input_block_queue_size` | Block Ingestion | Coordinator not consuming blocks fast enough |
| `sidecar_relay_mapped_block_queue_size` | Block Mapping | Blocks are mapped faster than the coordinator accepts them |
| `sidecar_relay_waiting_transactions_queue_size` | Relay | Transactions waiting for commit statuses to return |
| `sidecar_relay_output_committed_block_queue_size` | Committed Blocks | Committed blocks backing up; downstream consumers slow |
| `sidecar_notifier_input_block_queue_size` | Notification | Notifier not keeping up with committed blocks |
| `sidecar_notifier_input_status_queue_size` | Notification | Notifier not keeping up with status updates |
| `coordinator_verifier_input_batch_queue_size` | Signature Verification | Verifiers cannot keep up; add instances or CPU |
| `coordinator_verifier_output_batch_queue_size` | Verified → VC | VC services not consuming verified transactions fast enough |
| `coordinator_vcservice_output_batch_queue_size` | VC → Dep Graph | Dependency graph not processing validated results fast enough |
| `coordinator_vcservice_output_tx_status_batch_queue_size` | Status Response | Status responses backing up between VC and Coordinator |
| `vcservice_batcher_input_queue_size` | VC Intake | Coordinator submitting faster than the VC batches; first queue to fill |
| `vcservice_preparer_input_queue_size` | VC Preparation | Preparer workers saturated |
| `vcservice_validator_input_queue_size` | VC Validation | DB validation queries too slow; check connections or co-location |
| `vcservice_committer_input_queue_size` | VC Commit | DB commit throughput is the bottleneck; most common |
| `vcservice_txstatus_output_queue_size` | VC Status Output | Status responses backing up; Coordinator not consuming fast enough |

## 3. Sidecar

### `waiting-txs-limit`

Maximum number of transactions the Sidecar has sent to the Coordinator and is awaiting status for. The Sidecar acquires one slot per transaction before sending a block, including the transactions it rejects itself. A slot is released when the Coordinator returns the transaction's final status, or, for a held or halted checkpoint, its checkpoint feedback. When all slots are occupied, the Sidecar blocks on slot acquisition, which causes the internal block channel to fill up, and eventually the Sidecar stops pulling blocks from the ordering service.

This value directly controls how many transactions can be in-flight across the entire pipeline. With a low value (e.g., 100), the Sidecar sends 100 transactions and blocks until all complete — the pipeline runs in lock-step and throughput drops dramatically. With a very high value, more transactions queue across the pipeline, increasing memory and queuing latency. Config blocks trigger a full drain regardless of this value. Default: 100,000 (the sample configuration sets 20,000,000).

Keep this at or above the Coordinator's `dependency-graph.waiting-txs-limit`. Below it, the Sidecar's limit replaces the Coordinator's as the pipeline's in-flight window, and since throughput is the in-flight count divided by latency, a smaller window lowers throughput, not only latency.

### `ledger.sync-interval`

How often the block store calls `fsync` to durable storage. Every Nth block triggers a full sync; intermediate blocks are written without fsync. Config blocks and file rollovers always sync.

Each fsync is an expensive I/O operation. A low value (e.g., 1) syncs every block, which can bottleneck the block ingestion path. Higher values (100, 500+) significantly improve block append throughput by amortizing I/O cost. The tradeoff is durability — blocks lost on crash are recoverable from the ordering service. Default: 100.

### `ledger.disable-tx-id-index`

Drops the block store's transaction ID index, which `GetBlockByTxID` and `GetTxByID` use to find a transaction. Both queries fail once it is off.

This is the block store's dominant cost at high transaction rates, because it writes one index entry per transaction rather than per block, and its LevelDB compaction rewrites those entries as the index grows. On a cluster committing around 100,000 tx/s, a CPU profile of a saturated Sidecar attributed 35% of its samples to that compaction, with the index at 33 GB against 118 GB of blocks; committed throughput fell by roughly a third over an hour at a fixed offered rate as the index kept growing. A deployment that serves neither query is better off without it. Note that the index also selects the block store's on-disk format, so this setting can only be changed against an empty ledger directory. Default: false.

### `channel-buffer-size`

Buffer size for internal Go channels in the Sidecar — block delivery, committed blocks, and status updates. When a channel is full, the producing goroutine blocks until the consumer reads.

A small buffer (e.g., 1-10) tightly couples the Sidecar's internal stages: any slowdown in the relay to the Coordinator immediately stalls block delivery from the orderer. A larger buffer absorbs temporary throughput variations but uses more memory. Default: 100.

### `max-workers-for-tx-parsing` and `min-tx-parsing-batch-size`

`max-workers-for-tx-parsing` is the most goroutines one block's transactions are parsed on before the Sidecar sends the block to the Coordinator. Parsing covers each transaction's envelope, its classification, and its form checks. Only the TX ID dedup and the batch order stay on a single goroutine.

With 1 worker, one core's parsing rate caps the Sidecar. More workers help only on hosts with spare cores. The relay's sender and receiver, the block store, and the notifier need cores too. `min-tx-parsing-batch-size` is the fewest transactions one goroutine is given: a block is split into batches of at least this many, so a block with fewer than twice this many is parsed on one goroutine. Defaults: 1 and 256.

### `last-committed-block-set-interval`

How often the Sidecar sends the latest committed block number to the Coordinator. The Coordinator uses this for dependency resolution.

Minimal effect on steady-state throughput. Shorter intervals improve recovery speed after failures. Default: 5s.

### `checkpoint-hold-retry-interval`

How long the Sidecar waits before fetching a held `_checkpoint` block again. A checkpoint is held when its local snapshot hash is not ready. Default: 1m.

This setting applies only during a hold. A shorter interval retries sooner, but may cause extra session restarts while hashing is still in progress. The total wait also depends on the [snapshot hasher](snapshot-hasher.md)'s poll interval and hashing time.

### `notification.max-active-tx-ids`

Global limit on active transaction ID subscriptions across all notification streams. When exhausted, new subscriptions are partially rejected.

Too low causes clients to receive rejections under moderate load, forcing retries that increase end-to-end latency. Default: 100,000.

### `notification.max-tx-ids-per-request`

Maximum transaction IDs per single notification request. Requests exceeding this are rejected entirely.

Prevents individual clients from consuming a disproportionate share of the subscription budget in a single call. Default: 1,000.

### `server.max-concurrent-streams`

Maximum concurrent streaming RPCs (Deliver + Notification) per client connection. Each stream holds server resources (goroutines, buffers).

Too low limits client concurrency and can cause connection failures under load. Default: 10.

### What limits the Sidecar

`BenchmarkSidecarEndToEnd` (`service/sidecar/sidecar_bench_test.go`) runs the whole Sidecar on one machine. It receives blocks over Deliver, verifies their consenter signatures, parses them, sends them to a stub Coordinator over gRPC, collects the statuses, and appends the blocks to an on-disk ledger. It shows three limits. Each one hides the next, so deal with them in this order:

1. **Block size.** Two of the Sidecar's costs are per block, not per transaction: verifying the block's consenter signatures, and one `fsync` every `ledger.sync-interval` blocks. Below about 1,000 transactions per block, the Sidecar cannot reach half its throughput whatever else is set. Block verification alone (`BenchmarkVerifyBlock` in `utils/deliverorderer`) runs 7.58 times faster per transaction at 10,000 transactions per block than at 100.
2. **Garbage collection.** The Sidecar is limited by how fast it allocates, not by CPU. At the default `GOGC=100`, the collector runs almost all the time while most cores sit idle, and throughput follows the allocation rate closely. Raising `GOGC` and removing allocations buy the same thing, so their gains do not add up. If you raise `GOGC`, also set `GOMEMLIMIT` as a backstop, sized from the Sidecar's live heap, which `waiting-txs-limit` bounds.
3. **Parsing.** More `max-workers-for-tx-parsing` makes parsing several times faster (`BenchmarkMapBlockSize`), but adds nothing end to end while the ledger append is the slowest stage. Turn on `ledger.disable-tx-id-index` first if the deployment allows it; once the append is cheap, parallel parsing pays off.

A saturated Sidecar can look idle. Most of its per-block stages run on a single goroutine, and one busy core out of 64 is under 2% of the machine. Compare each stage's time per block with the budget instead: the block size divided by the target rate. At 10,000 transactions per block and 450,000 tx/s, the budget is 22.2 ms. On a nineteen-machine deployment, `sidecar_ledger_append_block_seconds` sat at that budget while the Sidecar used 18% of its cores. The stage histograms are `sidecar_ledger_append_block_seconds`, `sidecar_relay_block_mapping_seconds`, `sidecar_relay_mapped_block_processing_seconds` and `sidecar_delivery_block_verification_seconds`.

## 4. Coordinator

### `dependency-graph.num-of-local-dep-constructors`

Number of goroutines that process transaction batches in parallel to construct batch-level dependency graphs. Each worker processes one batch at a time, and output is serialized in FIFO order.

Increasing this parallelizes the CPU work of building dependency graphs. However, since output order is enforced via a condition variable, gains diminish beyond 2-4 workers. On some setups, more constructors bring no gain at all. `BenchmarkDependencyGraph` on a 32-core machine, with no dependencies between transactions, shows no trend from 1 to 32 constructors. There, the default manager is bound by its single graph goroutine and its single validated-batch goroutine, which more constructors do not widen. Raise this only if a profile shows the constructors themselves saturated. Default: 1.

### `dependency-graph.use-simple-manager`

Selects the simple dependency graph manager. The default manager splits the work between a pool of local dependency constructors and a global graph guarded by one mutex. The simple manager keeps the whole waiting set in one map, owned by one goroutine and fed by channels, with no lock. `num-of-local-dep-constructors` has no effect when it is on.

To see whether the lock is the problem, compare `coordinator_global_dependency_graph_validated_tx_batch_processing_seconds` with `coordinator_global_dependency_graph_validated_tx_batch_processor_wait_for_lock_seconds` and `coordinator_global_dependency_graph_constructor_wait_for_lock_seconds`. The wait metrics show how much of the graph's busy time is spent waiting for the mutex rather than working. On a nineteen-machine deployment, about 40% of each stage's busy time was lock wait, while no thread on the 64-core machine was above 20%.

Removing the contention does not raise throughput by itself. The released pressure moves to the next stage, so check what is behind the graph after switching: database commit latency, and the validator-committers' CPU. In that deployment, the simple manager committed 47.6% more than the default manager under the same configuration. Under the default manager the database was starved: its batch commits took 62 ms instead of 140 ms, and the commit machines were less busy, while the graph was full. That measurement had no key conflicts between transactions, which is the case that favors one goroutine. Default: false.

### `dependency-graph.waiting-txs-limit`

Maximum number of transactions in the global dependency graph. The Coordinator acquires one slot per transaction before adding it to the graph. Slots are released when the VC returns validation results. When exhausted, the dependency graph construction blocks, channels fill up, and the Sidecar stops pulling blocks.

The dependency graph is what enables parallel dispatch to Verifier and VC services. A small graph (e.g., 100) means once transactions are dispatched, no new ones enter until results return — creating idle gaps and reducing throughput. A very large graph increases memory for dependency tracking state and queuing latency. Incoming blocks are chunked into batches of `min(waiting-txs-limit, 500)` to prevent a single block from consuming all slots. Default: 100,000.

Oversizing it costs latency and memory without adding throughput. On a nineteen-machine deployment, lowering it from 20,000,000 to 500,000 kept the committed rate at about 500,000 tx/s, while mean latency fell from 2.48 s to 691 ms and the Coordinator's resident memory fell from 79 GB to 786 MB, about 4 KB per waiting transaction. Transactions beyond those needed to keep the validator-committers busy only wait, and by Little's law that waiting is latency. Size it from the in-flight count the pipeline needs, the rate times the pipeline's latency, not from what the machine can hold.

### `per-channel-buffer-size-per-goroutine`

Base buffer size for internal Go channels connecting the Coordinator's pipeline stages. The actual buffer for each channel is computed as base × number of endpoints (or constructors):

```
Coordinator → DepGraph:  base × num-of-local-dep-constructors
DepGraph → Verifier:     base × number-of-vc-endpoints
Verifier → VC:           base × number-of-verifier-endpoints
VC → DepGraph:           base × number-of-vc-endpoints
VC → Coordinator:        base × number-of-vc-endpoints
```

When a channel is full, the producing stage blocks. A small buffer means any momentary downstream slowdown immediately stalls all upstream stages. A larger buffer absorbs temporary throughput variations but increases memory and queuing latency. With 3 verifiers and 6 VCs, the defaults produce 30-60 item buffers per channel. Default: 10.

## 5. Verifier

### `parallel-executor.parallelism`

Number of goroutines that verify signatures in parallel. Signature verification is CPU-bound. Each stream from the Coordinator creates an independent executor with this many workers.

Set this to match the number of CPU cores available on the Verifier node. Under-setting leaves CPU idle, reducing verification throughput and causing transactions to queue at the Coordinator. Over-setting causes context switching overhead with no throughput gain. The default of 40 assumes a 32+ core machine.

### `parallel-executor.batch-size-cutoff`

Minimum number of verification results to collect before emitting a batch to the Coordinator. Results are buffered until this threshold is reached or `batch-time-cutoff` expires, whichever comes first.

Setting this too low causes many small batches to be emitted, increasing per-batch overhead in channel writes and gRPC communication. Setting this too high delays results — individual transactions wait longer for the batch to fill, increasing end-to-end latency.

| Setting | Throughput | Latency |
|---------|-----------|---------|
| 10-20 | Lower (more frequent, smaller batches) | Lower |
| 50 (default) | Good balance | Moderate |
| 100-200 | Higher (fewer, larger batches) | Higher |

### `parallel-executor.batch-time-cutoff`

Maximum time to wait for a batch to reach `batch-size-cutoff` before emitting a partial batch. This is the latency safety valve — without it, a partially filled batch under low load would wait indefinitely.

Setting this too low defeats batching (batches emit before they can fill). Setting this too high adds latency during periods of low or variable transaction arrival rates.

The default of 10ms ensures results are emitted promptly even under low load. Increase to 50-100ms only if batching efficiency is more important than latency.

### `parallel-executor.channel-buffer-size`

Buffer size for internal channels in the verification pipeline. The actual channel capacity is computed as:

```
capacity = channel-buffer-size × parallelism
```

With the defaults (50 buffer × 40 parallelism = 2,000 capacity). When the input channel is full, the Coordinator's dispatch to the Verifier blocks, which stalls the dependency graph. When the output channel is full, verification workers block, reducing effective parallelism.

Setting this too low causes frequent blocking that reduces the effective parallelism of the verification workers. Setting this too high increases memory usage proportionally. The defaults provide enough buffering for sustained high throughput.

## 6. Validator-Committer (VC)

The VC processes transactions through three pipeline stages: preparation, validation, and commit. Each stage has an independent worker pool. The overall throughput is limited by the slowest stage.

### `resource-limits.max-workers-for-preparer`

Number of goroutines that extract read/write sets from transactions and organize them for validation. Preparation is **CPU-bound** — it parses transaction payloads, builds namespace-to-reads maps, and categorizes writes.

Setting this too low makes the preparer the bottleneck — transactions queue up waiting for preparation while the validator and committer workers sit idle. Setting this higher than needed wastes CPU on goroutine overhead.

The default of 1 is sufficient for most workloads because preparation is fast relative to the database-bound stages. Increase to 2-4 if you observe the preparer queue growing while validator and committer queues are empty.

### `resource-limits.max-workers-for-validator`

Number of goroutines that perform MVCC validation against the database. Each worker calls a stored procedure (`validate_reads_ns_<namespace>`) that checks whether read set versions still match the committed state.

Validation is **database-bound** — each call makes at least one database round-trip per namespace in the transaction's read set. Each active validator worker holds a database connection for the duration of its query.

Setting this too low causes transactions to queue at the validator stage while the database has spare capacity. Setting this too high exhausts the connection pool — workers compete for connections, and the overhead of connection acquisition negates the parallelism benefit.

| Setting | Effect |
|---------|--------|
| 1 (default) | Serialized validation; minimal DB load; may under-utilize DB |
| 2-4 | Parallel validation; higher throughput; needs more DB connections |
| >4 | Diminishing returns unless DB can sustain the concurrent queries |

### `resource-limits.max-workers-for-committer`

Number of goroutines that commit validated transactions to the database using stored procedures (`insert_tx_status`, `insert_ns_<namespace>`, `update_ns_<namespace>`). Each commit involves multiple database round-trips within a transaction: writing transaction status, inserting new keys, and updating existing keys.

The committer is typically the **pipeline bottleneck** because it performs the most database work per transaction. Each active committer worker holds a database connection for the duration of the commit. When transactions complete here, slots are released in the Coordinator's dependency graph and the Sidecar's waiting-txs pool — so committer throughput directly controls how fast the entire pipeline can flow.

Setting this too low starves the pipeline — the Coordinator's dependency graph fills up, backpressure reaches the Sidecar, and block ingestion stalls. Setting this too high overwhelms the database with concurrent transactions, causing contention and increased retry rates.

| Setting | Effect |
|---------|--------|
| 1-2 | Low throughput; database under-utilized; pipeline stalls |
| 10-20 (default: 20) | Good throughput; recommended starting point |
| >20 | Diminishing returns; may overwhelm the database with contention |

### `resource-limits.min-transaction-batch-size`

Minimum number of transactions that must accumulate before the batch is forwarded to the preparation stage. The VC waits for this many transactions or until `timeout-for-min-transaction-batch-size` expires, whichever comes first. Config blocks are always sent immediately regardless of batch size.

Larger batches improve efficiency — stored procedures process keys in bulk, reducing per-transaction overhead. But larger batches also increase latency because early-arriving transactions wait for the batch to fill.

Setting this too high under low transaction rates causes transactions to sit idle until the timeout expires, adding `timeout-for-min-transaction-batch-size` of latency to every batch. Setting this to 1 (default) disables batching entirely — every transaction is forwarded immediately for lowest latency.

| Setting | Throughput | Latency |
|---------|-----------|---------|
| 1 (default) | Lower (no batching benefit) | Lowest |
| 10-50 | Higher (bulk stored procedure operations) | Higher (waits for batch to fill) |

### `resource-limits.timeout-for-min-transaction-batch-size`

Maximum time to wait for a batch to reach `min-transaction-batch-size`. This is the latency safety valve for batching — without it, a partially filled batch under low load would wait indefinitely.

When `min-transaction-batch-size` is 1, this timeout has no effect (batches are sent immediately). When `min-transaction-batch-size` is higher, this timeout determines the worst-case additional latency during low-throughput periods.

The default of 2s pairs with the default batch size of 1 (effectively unused). If you increase the batch size, consider reducing the timeout to 100-500ms to bound the latency impact.

### `database.max-connections`

Maximum number of connections in the database connection pool. The validator and committer stages share this pool (the preparer does not use the database — it performs in-memory parsing only). If the pool is exhausted, workers block waiting for a free connection, reducing effective parallelism.

Size the pool to accommodate concurrent usage:

```
Required connections >= max-workers-for-validator + max-workers-for-committer
```

Snapshot hashing does not draw from this pool at all: it runs in the separate snapshot hasher, against its own short-lived pool on the clone database (see [Snapshot Hasher](#8-snapshot-hasher)).

Setting this too low causes connection starvation — workers sit idle waiting for connections while the database has spare capacity. Setting this too high wastes database server memory and can cause connection-level contention.

The default of 10 is conservative and likely insufficient for production workloads with the default committer worker count of 20. Size this to at least match the total validator + committer worker count.

### `database.min-connections`

Minimum number of idle connections maintained in the pool. Keeps connections warm to avoid the overhead of establishing new connections (TCP handshake + TLS negotiation + authentication) under sudden load spikes. Set to roughly 50% of `max-connections`.

### `database.load-balance`

Enables client-side load balancing across multiple database endpoints. When enabled, each new connection is distributed across the configured endpoints.

- **`true`**: Required for YugabyteDB clusters to distribute operations across nodes and avoid hotspots. Without this, all connections go to the first endpoint, overloading one node while others sit idle.
- **`false`**: Use for single-node deployments.

### `database.table-pre-split-tablets`

Number of tablets to pre-split each table into at creation time (YugabyteDB only). Pre-splitting distributes data across tablet servers from the start, preventing the "hot tablet" bottleneck where a single tablet handles all initial writes before automatic splitting kicks in.

Without pre-splitting, the first hours of operation can see severe write latency spikes as all writes converge on a single tablet. Pre-splitting eliminates this problem entirely.

Set this to match the number of tablet servers in the cluster, or a small multiple (1x-2x). For example, with 9 tablet servers, set to 9 or 18.

When the database is PostgreSQL, this setting is automatically ignored.

| Setting | Effect |
|---------|--------|
| 0 (default) | No pre-splitting; hot tablet during initial writes; latency spikes |
| = tserver count | Even distribution from the start; predictable latency |
| 2x tserver count | Finer distribution; slightly more per-tablet overhead |

More tablets than tablet servers is a trade-off between writes and reads. A tablet is the unit of write concurrency, so more tablets raise insert throughput. But YugabyteDB batches a multi-key lookup such as `WHERE key = ANY($1)` only while the number of tablets times the number of keys stays below about 32,768. Above that, it sends one storage read per key. Measured on the same rows with 1,200 keys, 120 tablets issued 1,200 storage reads and took 7.80 s; the default split issued 2 and took 12.5 ms. The query plan is the same in both cases, so only `Storage Read Requests` from `EXPLAIN (ANALYZE, DIST)` shows it.

An insert-only workload never runs a multi-key lookup, so it does not show this. The validator-committer's blind-write path (`queryVersionsIfPresent`), read validation and the query service all do. On a nineteen-machine deployment with 12 tablet servers:

| Tablets | Insert-only workload | Workload with a multi-key read |
|---------|----------------------|--------------------------------|
| 120 | 487,000 tx/s | 13,200 tx/s |
| 12 | 360,000 tx/s | 314,000 tx/s |

The threshold also tightens over time. YugabyteDB splits tablets automatically as a table grows, so this setting is a starting count, not a ceiling: a table created with 120 tablets held 288 after eleven hours of load. The lasting lever is the number of keys per lookup, which the size of the validator-committer's batches sets. If you raise the tablet count for write throughput, measure a multi-key read before and after. The threshold above was found against YugabyteDB 2025.2.1.0; test it on your version.

### `database.retry`

Exponential backoff retry strategy for database operations. Required for YugabyteDB to handle retryable transaction conflicts (e.g., serialization failures from concurrent MVCC operations).

| Parameter | Default | Effect |
|-----------|---------|--------|
| `initial-interval` | 500ms | First retry delay |
| `randomization-factor` | 0.5 | Jitter range (+/- 50%) to avoid thundering herd |
| `multiplier` | 1.5 | Exponential backoff factor |
| `max-interval` | 60s | Cap on any single retry delay |
| `max-elapsed-time` | 15m | Total retry duration before giving up |

For high-throughput workloads with frequent transaction conflicts, reduce `initial-interval` to 100-200ms and `max-interval` to 10-30s to retry faster. Too-aggressive retries (very short intervals) can amplify contention under heavy load.

## 7. Query Service

### `min-batch-keys`

Minimum number of keys that must accumulate in a query batch before executing against the database. The batch is submitted when this threshold is reached or `max-batch-wait` expires, whichever comes first.

Batching reduces database round-trips by combining keys from multiple concurrent requests into a single query. Setting this too low sends many small queries, increasing per-query overhead. Setting this too high delays queries waiting for the batch to fill, increasing latency for individual requests.

| Setting | Throughput | Latency |
|---------|-----------|---------|
| 256-512 | Lower (smaller batches, more round-trips) | Lower |
| 1024 (default) | Good balance | Moderate |
| 2048-4096 | Higher (larger batches, fewer round-trips) | Higher |

### `max-batch-wait`

Maximum time to wait for a batch to reach `min-batch-keys`. This bounds the worst-case latency during low-load periods when keys accumulate slowly. Setting this too low defeats batching (queries execute before batches can fill). Setting this too high adds latency during quiet periods.

The default of 100ms is appropriate for most deployments. Reduce to 50ms for lower latency.

### `view-aggregation-window`

Time window for aggregating multiple views with the same parameters (isolation level, deferrable mode) into a single batched view. Views created within this window share the same batcher, reducing database load.

Setting this too low creates many independent batchers, each holding its own database connection — increasing connection pool pressure. Setting this too high delays the first query in a window, as new views must wait for the window to open a batcher.

The default of 100ms balances throughput and latency.

### `max-aggregated-views`

Maximum number of views that can be aggregated into a single batcher. Once reached, a new batcher is created even if within the `view-aggregation-window`. This prevents a single batcher from becoming a contention point under very high concurrency. The default of 1024 is appropriate for most deployments.

### `max-active-views`

Maximum concurrent active views across all clients. New `BeginView` requests are rejected with `RESOURCE_EXHAUSTED` when this limit is reached.

Setting this too low causes clients to receive errors during peak load, forcing retries that amplify latency. Setting this too high allows unbounded resource consumption. Set to 0 to disable the limit (not recommended in production). The default of 4096 is permissive.

### `max-view-timeout`

Maximum lifetime of a view from creation to completion. Views exceeding this timeout are aborted and their queries return errors. This prevents dangling views from holding resources indefinitely.

Setting this too low causes legitimate long-running queries to be aborted. Setting this too high allows idle or abandoned views to hold database connections for extended periods, reducing pool availability for other views.

This parameter interacts with the connection pool. The maximum number of database connections needed by the Query Service depends on:

```
max connections needed = (max-view-timeout / view-aggregation-window) × view-parameter-permutations
```

There are up to 8 view parameter permutations (4 isolation levels × 2 deferrable modes). With defaults: `(10s / 100ms) × 8 = 800`. In practice, not all permutations are used simultaneously, so fewer connections are needed. Monitor connection pool wait metrics to determine the right size.

### `max-request-keys`

Maximum number of keys allowed in a single query request. Applies to both `GetRows` (total keys across all namespaces) and `GetTransactionStatus` (number of transaction IDs). Setting this too low forces clients to split queries into many small requests, increasing round-trip overhead. Setting this too high allows individual requests to cause memory spikes and long-running queries that block the connection pool. The default of 10,000 is a reasonable balance.

### `database.max-connections` (Query Service)

The Query Service connection pool operates differently from the VC pool. Connections are held for the duration of a view's queries, which can be up to `max-view-timeout`. A view that holds a connection for 10 seconds blocks that connection from serving other views.

Size the pool based on expected concurrent view load and the formula above. The default of 10 is conservative — increase for production workloads. Monitor the connection pool wait metrics to detect when views are blocking on connection acquisition.

## 8. Snapshot Hasher

The snapshot hasher hashes snapshot clones. It is deployed as a single instance and does no per-transaction work, so its parameters trade hash latency against the read load it adds to a cluster that is also committing transactions.

It uses two pools with different sizing rules: the long-lived pool on the source database, governed by `database.max-connections`, only polls the latest snapshot record one statement at a time, so it needs very few connections; the per-job pool on the clone database is sized from `resource-limits.max-workers-for-hash` (see below). The hasher creates no tables, so `database.table-pre-split-tablets` has no effect here and is omitted from its sample config.

### `poll-interval`

How often the hasher re-reads the latest snapshot record looking for work. Nothing notifies it, so this interval *is* the scheduling latency: hashing begins within one interval of the snapshot committing, and after a restart the first check happens one interval in.

| Value | Effect |
|---|---|
| 1m (default) | One small indexed query per minute; hashing starts within a minute of the commit |
| Seconds | Hashing starts sooner, at the cost of a query per interval; useful when snapshots are frequent and hashes are awaited |
| Much higher | Fewer queries, but a snapshot can sit unhashed for that long, and a restart takes that long to resume |

Lowering it does not make hashing faster — only the wait before it starts. Hashing runs inline, so a job that outlives the interval simply delays the next check.

### `resource-limits.max-workers-for-hash`

Number of tables hashed in parallel within one hash job. Hashing is a full scan of every hashed table in the clone, so this is the main knob on how much read load a hash job adds.

This setting is also the clone pool's size. Each hash job opens its own short-lived pool against the clone database with exactly `max-workers-for-hash` connections, because at most one connection per worker is in use at any instant while it pages through its table; `database.max-connections` and `database.min-connections` are not used for that pool, since they size the long-lived pool that polls the snapshot record on the source database. So a hash job neither consumes another service's connection budget nor obeys this service's own pool settings — but the cluster must have headroom for those extra connections and their scan traffic.

| Setting | Effect |
|---------|--------|
| 1 | Serialized per-table hashing; lowest read load; slowest hash |
| 4 (default) | Parallel per-table hashing; good balance |
| >4 | Faster hashing on many-namespace deployments; competes with live traffic |

### `resource-limits.hash-batch-size`

Number of rows fetched per round-trip when scanning a table for hashing (keyset pagination). Larger batches reduce the number of round-trips but increase the memory held by each hashing worker; total memory scales with `max-workers-for-hash × hash-batch-size`, and it also depends on the size of the keys and values in the table being hashed. The default of 1000 keeps per-worker memory bounded on large tables.

## 9. Database

### YugabyteDB Considerations

- **Tablet distribution**: Use `table-pre-split-tablets` (VC config) to distribute tablets evenly across all tablet servers. Without pre-splitting, initial writes hit a single tablet, causing latency spikes until automatic splitting occurs.
- **Rebalancing**: After adding new tablet servers, rebalance tablets to distribute data to the new nodes.
- **Connection load balancing**: Enable `database.load-balance: true` on all services connected to YugabyteDB to distribute queries across nodes.

### PostgreSQL Considerations

- **`table-pre-split-tablets`**: Automatically ignored when PostgreSQL is detected.
- **Connection pool**: Same `max-connections` and `min-connections` parameters apply. Size based on concurrent query volume.
- **Replication**: For read-heavy workloads, configure Query Service instances to connect to read replicas.

## 10. Co-location Impact

MVCC validation requires multiple database round-trips per transaction — read set validation, write set application, and status updates. When VC instances are co-located with database nodes, each of these round-trips takes microseconds instead of milliseconds. Without co-location, expect significantly higher commit latency, which directly limits overall system throughput.

Co-location is most impactful for the VC service because it performs the most database operations per transaction. The Query Service benefits less because its read-only queries are less latency-sensitive.

## 11. A Starting Point for Large Deployments

The settings below sustained 500,000 tx/s, at about 392 ms mean end-to-end latency, on a nineteen-machine deployment. Use them as a starting point for a deployment of similar size, then tune with the sections above. They are not proposed as defaults: they fit one class of hardware and one workload shape.

**The deployment.** One Sidecar, one Coordinator, three Verifiers and six Validator-Committers, with YugabyteDB on 12 tablet servers and 3 masters. Each machine had 64 hardware threads and 156 GB of memory. Each Validator-Committer shared a machine with a tablet server, and the Sidecar, the Coordinator and each Verifier had a machine of their own. Blocks held 10,000 transactions. Each transaction had two read-write keys of 32 bytes with 32-byte values, and no two transactions touched the same key. At this rate the database was the limit, at 83% CPU and 88% disk busy, and every committer stage had headroom.

| Service | Setting | Value | Default | Why |
|---------|---------|-------|---------|-----|
| Sidecar | `ledger.disable-tx-id-index` | `true` | `false` | The index's compaction was the Sidecar's largest cost. Only if no client needs `GetBlockByTxID` or `GetTxByID`, and only on an empty ledger. |
| Sidecar | `channel-buffer-size` | 5 | 100 | A deep buffer only holds blocks waiting for their statuses. Mean latency fell from 6.36 s to 1.16 s at the same throughput. |
| Sidecar | `waiting-txs-limit` | 500,000 | 100,000 | At least the Coordinator's limit. |
| Sidecar | `max-workers-for-tx-parsing` | 16 | 1 | One goroutine caps parsing at one core. |
| Coordinator | `dependency-graph.use-simple-manager` | `true` | `false` | Removes the graph's lock contention. See its section: this workload had no key conflicts. |
| Coordinator | `dependency-graph.waiting-txs-limit` | 500,000 | 100,000 | Enough in flight to keep the six Validator-Committers busy at this rate. |
| VC | `resource-limits.max-workers-for-preparer` | 16 | 1 | Cheap stages; 16 keeps them idle. |
| VC | `resource-limits.max-workers-for-validator` | 16 | 1 | Same. |
| VC | `resource-limits.max-workers-for-committer` | 64 | 20 | The concurrency into the database: 6 × 64 = 384 batches. 40 workers committed 14.7% less. |
| VC | `database.max-connections` | 128 | 20 | Above the validator and committer workers together, so workers wait on the database, not on the pool. |
| VC | `database.min-connections` | 16 | 1 | Avoids opening connections during the ramp. |
| VC | `database.load-balance` | `true` | `false` | Spreads connections across the tablet servers. Every node must be in every database certificate's SANs, or all connections stay on one node. |
| VC | `database.table-pre-split-tablets` | 120 | none | Ten per tablet server, for write throughput. Use one per tablet server if the workload performs multi-key reads; see [`database.table-pre-split-tablets`](#databasetable-pre-split-tablets). |
| YugabyteDB | `--ysql_max_connections` | 500 | 300 | Six Validator-Committers × 128 connections, with headroom. |
| YugabyteDB | data directories | two per tablet server, on separate devices | | Disk is what limits the database at this rate. |

Everything else was left at its default. That includes gRPC flow control, whose defaults are the sizes from [Pipeline Flow Control](#1-pipeline-flow-control), and `GOGC` on the committer services.

To adapt it:

- **Block size is set by the ordering service.** Use at least about 1,000 transactions per block; below that, the Sidecar's per-block costs bind first. Larger blocks raise the Sidecar's ceiling and add latency.
- **Scale the Validator-Committers with the database.** Commit concurrency, the number of Validator-Committers times `max-workers-for-committer`, is what drives the database. Raise it only while the database has headroom.
- **Size the in-flight windows from the target rate.** Set the Coordinator's `dependency-graph.waiting-txs-limit` to about the target rate times the pipeline's latency, and the Sidecar's `waiting-txs-limit` at or above it.
- **Check the workload assumptions.** With no key conflicts, the dependency graph never holds a transaction back and MVCC validation never aborts one. Both the simple manager's gain and the pre-split's gain may be smaller under contention. Write contention at a back-reference rate of 0.5 cost about 19% in the same deployment, with 12 tablets.

## 12. Benchmarking

The tuning recommendations in this guide are starting points, not guarantees. Real performance depends on factors specific to your deployment:

- Transaction size and complexity (number of read/write keys per transaction)
- Number of namespaces and endorsement policy complexity
- Read set and write set sizes
- Network topology and latency between nodes
- Storage hardware characteristics

Benchmark with your actual workload on your target hardware to establish baseline performance and identify the tuning parameters that matter most for your use case.
