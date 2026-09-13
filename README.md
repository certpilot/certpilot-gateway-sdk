# certpilot-gateway-sdk

The contract between the [CertPilot](https://github.com/certpilot/certpilot)
core and a certificate authority gateway, published so that a gateway can be
written without commit access to the core.

A **gateway** is a small gRPC server that speaks to one certificate authority.
The core asks it to issue, renew and revoke; it translates that into whatever
the CA in front of it actually wants — ACME, a Vault PKI mount, a vendor REST
API — and answers in the shapes defined here.

```
go get github.com/certpilot/certpilot-gateway-sdk
```

## What is in here

| Package | |
|:---|:---|
| `pb/provider/v1` | the service, generated. `RegisterCertificateProviderServiceServer` is what you implement |
| `pb/common/v1` | `CertificateInfo` and the shared enums |
| `grpckit` | the mutually-authenticated server and dialer both ends use, and a dev PKI generator |
| `x509util` | parsing a CSR or a certificate into the fields the contract wants |
| `crypto` | key generation and CSR building, for gateways that generate keys themselves |
| `proto/` | the source of truth. `pb/` is generated from it and committed |

Nothing here imports the core, and nothing here imports the agent SDK. That is
checked, not assumed — an SDK that reaches into the thing it is an interface to
is not publishable, and the day you discover that is the day you try to move it.

## Writing one

Eight methods. Four of them are metadata and take an afternoon; the three
lifecycle calls are the work, and `ValidateConfig` is what makes a
misconfiguration visible before a certificate depends on it.

The long-form guide is
[`docs/writing-a-gateway.md`](https://github.com/certpilot/certpilot/blob/main/docs/writing-a-gateway.md)
in the core repository. Four things in it are worth repeating here, because
each one has been got wrong at least once:

- **`csr_pem` is part of the contract.** When it is present, sign the key you
  were given. Generating your own instead silently discards the key the caller
  is about to deploy, and the failure surfaces much later as a certificate that
  does not match its private key.
- **`GetCAInfo` is what puts issuers into the inventory.** Return the issuers
  behind the account and they become monitored, thresholded and alerted on like
  everything else. Return nothing and the CA is invisible until it expires.
- **A gateway holds no credential of its own.** Each CA account carries the
  identity it issues under, and it arrives in `provider_config`. A gateway
  process that can sign something on its own is a gateway process worth
  stealing.
- **Never report success for work you did not do.** An error is recoverable.
  A success that issued nothing becomes a record of a certificate that does not
  exist, and everything downstream — renewal, revocation, expiry — then acts on
  a fiction.

## Registering it

A gateway is reachable over the network, so the core does not need to have
heard of it:

```
POST /api/v1/ca-accounts   { "gateway_addr": "gateway.internal:9443", ... }
```

The channel carries CSRs, private keys and CA credentials, so it is mutually
authenticated by default. `grpckit.NewServer` expects that; `GenerateDevPKI`
writes material for local work.

## The compatibility promise

**A version here is a promise about a wire contract, not about a Go API.**

The reason to say that out loud is that the two come apart. Generated protobuf
code changes shape for reasons that have nothing to do with the wire — a
regenerated file can move a struct field and break a Go build while every byte
on the network stays identical. If that were allowed to force a major version,
`v1` would stop meaning anything within a year.

So, for as long as this module is `v1`:

- **A gateway built against any `v1.x` keeps working against any core that
  speaks `provider.v1`.** Two minor versions ahead, ten — it keeps working, or
  the change that broke it was a mistake and gets reverted.
- **New fields are added, never renumbered or reused.** A field the other end
  does not know about is ignored, which is the property the whole scheme rests
  on.
- **New RPCs may be added.** A core that calls one your gateway does not
  implement gets `Unimplemented`, and that is a supported answer, not a crash.
- **Nothing is removed and nothing changes meaning inside `v1`.** A breaking
  change to the wire is `provider.v2`, served alongside `v1` for as long as it
  takes.

What is *not* promised: `grpckit`, `x509util` and `crypto` are ordinary Go
packages and follow ordinary Go semver. They are conveniences. If one of them
ever gets in your way, implement the generated interface directly — that is the
contract, and the rest is help.

## Regenerating

```
make proto        # buf generate
make proto-lint   # buf lint
```

`pb/` is generated **and committed**, which is what makes a fresh clone
buildable without `buf` and without network. The cost of committing generated
code is that it can drift from the `.proto` that produced it, silently, so CI
regenerates on every pull request and fails if the result differs.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
