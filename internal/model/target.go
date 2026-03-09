package model

type HttpxTarget struct {
	Host     string `json:"host" bson:"host"`
	IP       string `json:"ip" bson:"ip"`
	Port     int    `json:"port" bson:"port"`
	Protocol string `json:"protocol" bson:"protocol"`
}

type HostIPMapping struct {
	Host string   `json:"host" bson:"host"`
	IPs  []string `json:"ips" bson:"ips"`
}

type PortChunk struct {
	Start int `json:"start"`
	End   int `json:"end"`
}
