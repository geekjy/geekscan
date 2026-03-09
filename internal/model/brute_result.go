package model

type BruteResult struct {
	Host     string `json:"host" bson:"host"`
	IP       string `json:"ip" bson:"ip"`
	Port     int    `json:"port" bson:"port"`
	Service  string `json:"service" bson:"service"`
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
	Success  bool   `json:"success" bson:"success"`
	TimedOut bool   `json:"timed_out" bson:"timed_out"`
}

var PortServiceMap = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	445:   "smb",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	6379:  "redis",
	27017: "mongodb",
}
