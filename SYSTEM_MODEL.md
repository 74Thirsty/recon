Canonical System Scope, Invariants, and Responsibilities (LOCKED)

Purpose

This document defines the authoritative system model for the pipeline:

Fetch -> Normalize -> Graph -> Scan -> Validate -> Execute

It exists to permanently prevent:
- graph / execution conflation
- silent data loss
- fabricated defaults
- fake compatibility rules
- recomputation of known data
- protocol semantic violations

If code disagrees with this document, the code is wrong.

The Entire System (Non-Negotiable)

The system does exactly this, in order:
1. Fetch data
2. Normalize data
3. Build a graph
4. Run algorithms on the graph
5. Validate cycles
6. Execute cycles

There are no hidden phases, no parallel models, no alternate interpretations.

1. Data Fetch

What Fetch Means
- Raw data is fetched from subgraphs and on-chain sources.
- This includes:
  - tokens
  - pools
  - balances
  - protocol metadata
  - loan availability data
  - prices (where available from subgraphs)

Fetch is:
- protocol-specific
- lossy-free
- execution-agnostic

Fetch does not:
- validate
- normalize
- build graphs
- encode execution

2. Normalization

What Normalization IS

Normalization performs value normalization only.

Specifically:
- Token decimals -> integer Wei
- Numeric units made consistent
- Token identities canonicalized
- Numeric hygiene enforced (finite, sane values)

Normalization applies to:
- tokens
- pools
- loan data
- prices

What Normalization IS NOT

Normalization does NOT:
- reshape protocol data
- change execution shape
- abstract ABI semantics
- encode calldata
- invent canonical interfaces
- infer missing data

Normalization fixes numbers. Nothing else.

3. Graph Construction

What the Graph Is

The graph is:
- token-native
- directed
- passive
- data-only

The graph has ZERO logic.

It does not:
- validate
- decide
- execute
- infer
- fabricate

Graph Contents

Each edge in the graph MUST contain everything required for scanners and downstream execution, including:
- src token
- dst token
- weight
- capacity
- protocol identifier
- pool / route identifiers
- execution keys
- loan-related metadata
- any other data that must survive until validation / execution

Edge Acceptance Rule

An edge is handled in exactly one of two ways:

ACCEPT
If:
- all required fields are present
- values are structurally valid
- the data was produced upstream

DROP
If:
- a required field was never produced
- the data is malformed, impossible, or nonsensical

Absolute Prohibitions (Graph)

The graph must never:
- invent defaults
- coerce missing values
- insert sentinels
- auto-patch upstream failures
- "helpfully" fabricate weight or capacity
- validate feasibility or profitability
- encode execution logic

If data is missing and was not lost, the edge is dropped.

4. Metadata (CRITICAL)

What Metadata Is For

Metadata exists to ensure nothing required downstream is ever lost.

If a piece of information is:
- known at fetch or normalization time
- required for validation or execution later

It MUST be stored as metadata and MUST persist unchanged.

Metadata MUST Preserve

This includes (non-exhaustive):
- loan availability data
- loan provider identifiers
- loan split constraints
- execution prerequisites
- callback requirements
- route / pool identifiers
- protocol-specific execution hints

Metadata is data, not logic.

Explicitly NOT Allowed
- Dropping loan information
- Recomputing loan splits "later"
- Re-deriving metadata
- Treating metadata as optional
- Losing metadata between phases

If it's needed later, it is stored now.

5. Loan Providers (Important Correction)

Canonical Rule

There is NO such thing as "loan provider compatibility."

All loan providers are compatible.

There is:
- no compatibility matrix
- no protocol pairing restriction
- no filtering based on swap protocol

Loan feasibility depends only on data availability, not compatibility.

What "Incompatible Loan Provider" REALLY Means

That message is invalid and misleading.

It actually indicates:
- missing loan data
- dropped metadata
- missing liquidity values
- a guard returning empty data

This log message must be removed or renamed to reflect data absence, not compatibility.

6. Topology Invariants
- Graph topology is static
- Topology includes:
  - nodes
  - edges
  - execution metadata
  - loan metadata

Topology changes only if upstream structural data changes.

Topology does not change due to:
- price updates
- liquidity updates
- refresh cadence
- time

7. Dynamic Fields

The following fields are dynamic:
- weight
- capacity
- price-derived metrics

Rules:
- refreshed in place
- never cause topology rebuild
- never cause edge re-emission
- never fabricate defaults

8. Persistence
- Graph is persisted verbatim
- On restart:
  - topology reloads unchanged
  - metadata reloads unchanged
  - Only dynamic fields may be refreshed

No recomputation.
No inference.
No silent fixes.

9. Scanning (Algorithms)
- Algorithms consume the graph as-is
- Algorithms discover cycles
- Algorithms do not mutate the graph
- Algorithms assume the graph is complete

Examples:
- RPZE
- Bellman-Ford

10. Validation
- Validation happens after scanning
- Validation is not part of the graph
- Validation checks:
  - feasibility
  - liquidity sufficiency
  - loan availability
  - profit constraints

Validation logic must never leak into graph construction.

11. Execution

Execution Model

Execution:
- occurs after validation
- uses dynamic ABIs
- obeys protocol-defined execution shape
- never forces canonical execution

Execution is driven by:
- protocol identifier
- execution keys
- protocol ABI
- runtime parameters

ABI Handling
- ABI shape is law
- ABI encoding happens at execution time
- Callback / loan framing is respected exactly
- The system executes the protocol's way

Final Laws (Locked)
- The graph has zero logic
- The graph never validates
- Normalization fixes numbers only
- Metadata must never be lost
- Loan providers are universally compatible
- Topology is static
- Liquidity and price are dynamic
- Execution encoding is last-mile and dynamic

Canonical One-Line Summary

We fetch data, normalize numeric values, build a passive token graph carrying all required metadata, run algorithms to find cycles, validate those cycles, and dynamically execute them using protocol-defined ABIs.
