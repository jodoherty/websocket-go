module github.com/jodoherty/websocket-go/e2e/h3

go 1.26.0

require (
	github.com/jodoherty/websocket-go v0.0.0
	github.com/quic-go/quic-go v0.63.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/jodoherty/websocket-go => ../../
