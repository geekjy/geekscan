package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Dictionary struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Type        string             `json:"type" bson:"type"` // "dir", "file", "api", "user", "password", "custom"
	FileID      primitive.ObjectID `json:"file_id" bson:"file_id"`
	LineCount   int                `json:"line_count" bson:"line_count"`
	Size        int64              `json:"size" bson:"size"`
	IsBuiltin   bool               `json:"is_builtin" bson:"is_builtin"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at" bson:"updated_at"`
}
