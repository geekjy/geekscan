package store

import (
	"context"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ResultStore struct {
	db *MongoDB
}

func NewResultStore(db *MongoDB) *ResultStore {
	return &ResultStore{db: db}
}

func (s *ResultStore) col() string { return "results" }

func (s *ResultStore) SaveBatch(ctx context.Context, taskID primitive.ObjectID, resultType string, data []interface{}) error {
	if len(data) == 0 {
		return nil
	}
	docs := make([]interface{}, len(data))
	now := time.Now()
	for i, d := range data {
		docs[i] = model.ScanResult{
			TaskID:   taskID,
			Type:     resultType,
			Data:     d,
			CreateAt: now,
		}
	}
	_, err := s.db.Collection(s.col()).InsertMany(ctx, docs)
	return err
}

func (s *ResultStore) GetByTaskID(ctx context.Context, taskID primitive.ObjectID, resultType string, skip, limit int64) ([]*model.ScanResult, int64, error) {
	filter := bson.M{"task_id": taskID}
	if resultType != "" {
		filter["type"] = resultType
	}

	col := s.db.Collection(s.col())
	total, err := col.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetSkip(skip).
		SetLimit(limit)

	cursor, err := col.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var results []*model.ScanResult
	if err := cursor.All(ctx, &results); err != nil {
		return nil, 0, err
	}
	for _, r := range results {
		r.Data = bsonDToMap(r.Data)
	}
	return results, total, nil
}

func bsonDToMap(v interface{}) interface{} {
	switch val := v.(type) {
	case bson.D:
		m := make(map[string]interface{}, len(val))
		for _, e := range val {
			m[e.Key] = bsonDToMap(e.Value)
		}
		return m
	case bson.A:
		a := make([]interface{}, len(val))
		for i, item := range val {
			a[i] = bsonDToMap(item)
		}
		return a
	default:
		return v
	}
}

func (s *ResultStore) DeleteByTaskID(ctx context.Context, taskID primitive.ObjectID) error {
	_, err := s.db.Collection(s.col()).DeleteMany(ctx, bson.M{"task_id": taskID})
	return err
}
