package store

import (
	"context"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ProviderStore struct {
	db *MongoDB
}

func NewProviderStore(db *MongoDB) *ProviderStore {
	return &ProviderStore{db: db}
}

func (s *ProviderStore) col() string { return "provider_configs" }

func (s *ProviderStore) Upsert(ctx context.Context, cfg *model.ProviderConfig) error {
	cfg.UpdatedAt = time.Now()
	filter := bson.M{"provider": cfg.Provider}

	var existing model.ProviderConfig
	err := s.db.Collection(s.col()).FindOne(ctx, filter).Decode(&existing)
	if err != nil {
		cfg.CreatedAt = time.Now()
		res, err := s.db.Collection(s.col()).InsertOne(ctx, cfg)
		if err != nil {
			return err
		}
		cfg.ID = res.InsertedID.(primitive.ObjectID)
		return nil
	}

	_, err = s.db.Collection(s.col()).UpdateOne(ctx, filter, bson.M{"$set": bson.M{
		"api_key":    cfg.APIKey,
		"api_secret": cfg.APISecret,
		"enabled":    cfg.Enabled,
		"updated_at": cfg.UpdatedAt,
	}})
	return err
}

func (s *ProviderStore) List(ctx context.Context) ([]*model.ProviderConfig, error) {
	cursor, err := s.db.Collection(s.col()).Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var configs []*model.ProviderConfig
	if err := cursor.All(ctx, &configs); err != nil {
		return nil, err
	}
	return configs, nil
}

func (s *ProviderStore) GetEnabled(ctx context.Context) ([]*model.ProviderConfig, error) {
	cursor, err := s.db.Collection(s.col()).Find(ctx, bson.M{"enabled": true})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var configs []*model.ProviderConfig
	if err := cursor.All(ctx, &configs); err != nil {
		return nil, err
	}
	return configs, nil
}

func (s *ProviderStore) Delete(ctx context.Context, provider string) error {
	_, err := s.db.Collection(s.col()).DeleteOne(ctx, bson.M{"provider": provider})
	return err
}
