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

Current release: **v0.2.0**. The three gateways CertPilot maintains build
against it with no `replace` directive, from their own repositories — which is
the only real test of whether this is published or merely copied.

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

## Checking it

```
go run github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@latest \
    -addr localhost:9443 -insecure -domain test.example.com
```

It makes real calls and prints sentences:

```
provider.v1 conformance — 127.0.0.1:19091

  ok    GetCapabilities                          selfsigned (selfsigned), key types RSA, ECDSA, Ed25519
  ok    ValidateConfig (rejects malformed JSON)  this is not valid JSON: invalid character 'h'
  ok    IssueCertificate (honours csr_pem)       signed the supplied key, returned no private key
  --    RevokeCertificate                        skipped: the gateway reports supports_revocation=false
```

The three gateways in the CertPilot tree are kept honest by live tests against a
real Vault and a real ACME server, which you cannot run. This is the
substitute — without something equivalent, "write your own gateway" means
"write your own and find out in production".

A skipped check never fails the run, and the report says so at the end rather
than letting a run that tested four things be remembered as "conformance
passed".

**The check worth knowing about before you start** is `IssueCertificate
(honours csr_pem)`. It issues against a CSR it generated and compares the public
key in the certificate you return against the one it asked you to sign. A
gateway that generates its own key instead passes every test its author is
likely to write, and fails much later as a certificate that does not match its
private key.

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

**The promise is about the wire, and it is not the module's version number.**

Two different things get versioned here and conflating them is how a promise
like this rots:

| | |
|:---|:---|
| `provider.v1` | the **wire contract** — the proto package. This is what a gateway actually implements, and what the promise below is about |
| `v0.x.y` on the Go module | the **Go API** of this repository: `grpckit`, `x509util`, `crypto`, and the shape of the generated structs |

They come apart constantly. A regenerated protobuf file can move a struct field
and break a Go build while every byte on the network stays identical. If that
were allowed to force a major version, the wire version would stop meaning
anything within a year.

### What is promised, starting now

Not "once we reach v1.0.0" — from the first tag onward, because the contract
below has been in production across three gateways for the life of the project
and the module version says nothing about it:

- **A gateway that implements `provider.v1` keeps working against any core that
  speaks `provider.v1`.** Two minor versions ahead, ten — it keeps working, or
  the change that broke it was a mistake and gets reverted.
- **New fields are added, never renumbered or reused.** A field the other end
  does not know about is ignored, which is the property the whole scheme rests
  on.
- **New RPCs may be added.** A core that calls one your gateway does not
  implement gets `Unimplemented`, and that is a supported answer, not a crash.
- **Nothing is removed and nothing changes meaning inside `provider.v1`.** A
  breaking change to the wire is `provider.v2`, served alongside `v1` for as
  long as it takes.

`buf breaking` enforces every line of that on each pull request. It is the only
part of this README that is checked rather than asserted, which is why it is
worth more than the rest of the section.

### What is not promised yet

**The Go API, while the module is `v0.x`.** `grpckit`, `x509util` and `crypto`
are conveniences, this is their first release outside the tree that grew them,
and the honest thing is to say they may move rather than to tag `v1.0.0` today
and discover the same week that one of them wants a different signature. Pin an
exact version.

`v1.0.0` is for when a gateway written outside this repository has actually
been built against these packages and they have survived the contact. If one of
them gets in your way before then, implement the generated interface directly
— that is the contract, and the rest is help.

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
