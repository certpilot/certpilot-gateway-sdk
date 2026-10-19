// The contract between the CertPilot core and a certificate authority gateway.
//
// Published separately from the core so that a gateway can be written without
// commit access to it.
//
// The stable thing here is the wire contract, `provider.v1`, not this module's
// version: a regenerated protobuf file can move a Go struct field while every
// byte on the network stays identical. README.md states which of the two each
// promise attaches to.
module github.com/certpilot/certpilot-gateway-sdk

go 1.26.9

require (
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
