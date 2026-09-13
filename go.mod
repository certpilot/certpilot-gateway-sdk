// The contract between the CertPilot core and a certificate authority gateway.
//
// Published separately from the core so that a gateway can be written without
// commit access to it. A version here is a promise about a wire contract
// rather than a Go API; see README.md, which states that promise in full.
module github.com/certpilot/certpilot-gateway-sdk

go 1.26.6

require (
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
