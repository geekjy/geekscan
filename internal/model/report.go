package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Report struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	TaskID    primitive.ObjectID `json:"task_id" bson:"task_id"`
	Format    string             `json:"format" bson:"format"` // "html", "pdf", "json"
	FilePath  string             `json:"file_path" bson:"file_path"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}
