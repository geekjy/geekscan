package store

import (
	"context"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type TaskStore struct {
	db *MongoDB
}

func NewTaskStore(db *MongoDB) *TaskStore {
	return &TaskStore{db: db}
}

func (s *TaskStore) col() string { return "tasks" }

func (s *TaskStore) Create(ctx context.Context, task *model.ScanTask) error {
	task.CreatedAt = time.Now()
	task.UpdatedAt = time.Now()
	if task.Status == "" {
		task.Status = model.TaskStatusPending
	}
	res, err := s.db.Collection(s.col()).InsertOne(ctx, task)
	if err != nil {
		return err
	}
	task.ID = res.InsertedID.(primitive.ObjectID)
	return nil
}

func (s *TaskStore) GetByID(ctx context.Context, id primitive.ObjectID) (*model.ScanTask, error) {
	var task model.ScanTask
	err := s.db.Collection(s.col()).FindOne(ctx, bson.M{"_id": id}).Decode(&task)
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *TaskStore) List(ctx context.Context, skip, limit int64) ([]*model.ScanTask, int64, error) {
	col := s.db.Collection(s.col())
	total, err := col.CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, 0, err
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetSkip(skip).
		SetLimit(limit)

	cursor, err := col.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var tasks []*model.ScanTask
	if err := cursor.All(ctx, &tasks); err != nil {
		return nil, 0, err
	}
	return tasks, total, nil
}

func (s *TaskStore) UpdateStatus(ctx context.Context, id primitive.ObjectID, status model.TaskStatus) error {
	_, err := s.db.Collection(s.col()).UpdateOne(ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"status": status, "updated_at": time.Now()}},
	)
	return err
}

func (s *TaskStore) Update(ctx context.Context, id primitive.ObjectID, update bson.M) error {
	update["updated_at"] = time.Now()
	_, err := s.db.Collection(s.col()).UpdateOne(ctx,
		bson.M{"_id": id},
		bson.M{"$set": update},
	)
	return err
}

func (s *TaskStore) Delete(ctx context.Context, id primitive.ObjectID) error {
	_, err := s.db.Collection(s.col()).DeleteOne(ctx, bson.M{"_id": id})
	return err
}
