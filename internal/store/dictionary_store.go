package store

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
)

type DictionaryStore struct {
	db *MongoDB
}

func NewDictionaryStore(db *MongoDB) *DictionaryStore {
	return &DictionaryStore{db: db}
}

func (s *DictionaryStore) col() string { return "dictionaries" }

func (s *DictionaryStore) Create(ctx context.Context, dict *model.Dictionary, content []byte) error {
	bucket, err := gridfs.NewBucket(s.db.Database)
	if err != nil {
		return err
	}

	uploadStream, err := bucket.OpenUploadStream(dict.Name)
	if err != nil {
		return err
	}
	defer uploadStream.Close()

	if _, err := io.Copy(uploadStream, bytes.NewReader(content)); err != nil {
		return err
	}

	dict.FileID = uploadStream.FileID.(primitive.ObjectID)
	dict.Size = int64(len(content))
	dict.CreatedAt = time.Now()
	dict.UpdatedAt = time.Now()

	res, err := s.db.Collection(s.col()).InsertOne(ctx, dict)
	if err != nil {
		return err
	}
	dict.ID = res.InsertedID.(primitive.ObjectID)
	return nil
}

func (s *DictionaryStore) List(ctx context.Context) ([]*model.Dictionary, error) {
	cursor, err := s.db.Collection(s.col()).Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var dicts []*model.Dictionary
	if err := cursor.All(ctx, &dicts); err != nil {
		return nil, err
	}
	return dicts, nil
}

func (s *DictionaryStore) GetByID(ctx context.Context, id primitive.ObjectID) (*model.Dictionary, error) {
	var dict model.Dictionary
	err := s.db.Collection(s.col()).FindOne(ctx, bson.M{"_id": id}).Decode(&dict)
	if err != nil {
		return nil, err
	}
	return &dict, nil
}

func (s *DictionaryStore) GetContent(ctx context.Context, fileID primitive.ObjectID) ([]byte, error) {
	bucket, err := gridfs.NewBucket(s.db.Database)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := bucket.DownloadToStream(fileID, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *DictionaryStore) Delete(ctx context.Context, id primitive.ObjectID) error {
	dict, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if dict.IsBuiltin {
		return nil
	}

	bucket, err := gridfs.NewBucket(s.db.Database)
	if err != nil {
		return err
	}
	_ = bucket.Delete(dict.FileID)

	_, err = s.db.Collection(s.col()).DeleteOne(ctx, bson.M{"_id": id})
	return err
}

var builtinDictTypes = map[string]string{
	"common.txt":           "dir",
	"api-endpoints.txt":    "api",
	"sensitive-files.txt":  "file",
	"users-common.txt":     "user",
	"passwords-common.txt": "password",
}

func (s *DictionaryStore) SeedBuiltinDictionaries(ctx context.Context, dictDir string) error {
	entries, err := os.ReadDir(dictDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}

		count, _ := s.db.Collection(s.col()).CountDocuments(ctx, bson.M{
			"name":       entry.Name(),
			"is_builtin": true,
		})
		if count > 0 {
			continue
		}

		content, err := os.ReadFile(filepath.Join(dictDir, entry.Name()))
		if err != nil {
			logger.L.Warnw("failed to read builtin dictionary file", "file", entry.Name(), "error", err)
			continue
		}

		lineCount := 0
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) != "" {
				lineCount++
			}
		}

		dictType := builtinDictTypes[entry.Name()]
		if dictType == "" {
			dictType = "custom"
		}

		dict := &model.Dictionary{
			Name:      entry.Name(),
			Type:      dictType,
			LineCount: lineCount,
			IsBuiltin: true,
		}

		if err := s.Create(ctx, dict, content); err != nil {
			logger.L.Warnw("failed to seed builtin dictionary", "file", entry.Name(), "error", err)
			continue
		}
		logger.L.Infow("seeded builtin dictionary", "name", entry.Name(), "lines", lineCount)
	}
	return nil
}
