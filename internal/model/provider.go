package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ProviderConfig struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Provider  string             `json:"provider" bson:"provider"`
	APIKey    string             `json:"api_key" bson:"api_key"`
	APISecret string             `json:"api_secret" bson:"api_secret"`
	Enabled   bool               `json:"enabled" bson:"enabled"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time          `json:"updated_at" bson:"updated_at"`
}

var SupportedProviders = []string{
	"shodan", "censys", "securitytrails", "virustotal", "chaos",
	"fofa", "hunter", "quake", "zoomeye",
	"binaryedge", "passivetotal",
	"github", "gitlab",
	"awvs",
}
