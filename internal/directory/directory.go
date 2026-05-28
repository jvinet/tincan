package directory

import "time"

const SchemaVersion uint32 = 1

type Directory struct {
	SchemaVersion uint32    `msgpack:"v"`
	Serial        uint64    `msgpack:"s"`
	CreatedAt     time.Time `msgpack:"t"`
	NetworkCIDR   string    `msgpack:"cidr"`
	Nodes         []Node    `msgpack:"nodes"`
}

type Node struct {
	Name             string    `msgpack:"n"`
	PublicKey        string    `msgpack:"pk"`
	TunnelIP         string    `msgpack:"ip"`
	Endpoint         string    `msgpack:"ep,omitempty"`
	ObservedEndpoint string    `msgpack:"oep,omitempty"`
	ObservedAt       time.Time `msgpack:"oat,omitempty"`
	PSK              string    `msgpack:"psk,omitempty"`
}

type Envelope struct {
	Payload   []byte `msgpack:"p"`
	Signature []byte `msgpack:"sig"`
}
