package website

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
)

const (
	defaultLinterBucket = "osv-test-public-import-logs"
	linterPrefix        = "linter-result/"
)

func linterBucket() string {
	if b := os.Getenv("OSV_LINTER_BUCKET"); b != "" {
		return b
	}

	return defaultLinterBucket
}

// handleLinterPage handles serving the linter findings UI page.
func (s *Server) handleLinterPage(w http.ResponseWriter, r *http.Request) {
	data := LinterPageData{
		BasePageData: BasePageData{
			ActiveSection: "linter",
		},
	}

	s.renderStandalone(w, r, "linter.html", http.StatusOK, data)
}

// handleLinterSources handles listing sources that have linter findings from GCS.
func (s *Server) handleLinterSources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	client, err := storage.NewClient(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create storage client for sources", slog.Any("err", err))
		http.Error(w, "Failed to connect to storage", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	bucketName := linterBucket()
	it := client.Bucket(bucketName).Objects(ctx, &storage.Query{
		Prefix:    linterPrefix,
		Delimiter: "/",
	})

	sources := make([]string, 0)
	for {
		attrs, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			logger.ErrorContext(ctx, "Failed to iterate linter sources from GCS", slog.Any("err", err))
			http.Error(w, "Failed to list sources", http.StatusInternalServerError)
			return
		}
		if attrs.Prefix != "" {
			name := path.Base(attrs.Prefix)
			if name != "" && name != "." {
				sources = append(sources, name)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sources); err != nil {
		logger.ErrorContext(ctx, "Failed to encode sources JSON", slog.Any("err", err))
	}
}

// handleLinterFindings handles fetching linter findings JSON for a specific source from GCS.
func (s *Server) handleLinterFindings(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	if source == "" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	client, err := storage.NewClient(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create storage client for findings", slog.Any("err", err))
		http.Error(w, "Failed to connect to storage", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	bucketName := linterBucket()
	objPath := path.Join(linterPrefix, source, "result.json")
	reader, err := client.Bucket(bucketName).Object(objPath).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			http.NotFound(w, r)
			return
		}
		logger.ErrorContext(ctx, "Failed to read linter findings from GCS", slog.Any("err", err), slog.String("path", objPath))
		http.Error(w, "Failed to read findings", http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/json")
	if _, err := io.Copy(w, reader); err != nil {
		logger.ErrorContext(ctx, "Failed to stream findings JSON", slog.Any("err", err))
	}
}

// handleLinterSummary handles fetching linter summary JSON from GCS.
func (s *Server) handleLinterSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	client, err := storage.NewClient(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create storage client for summary", slog.Any("err", err))
		http.Error(w, "Failed to connect to storage", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	bucketName := linterBucket()
	objPath := path.Join(linterPrefix, "summary.json")
	reader, err := client.Bucket(bucketName).Object(objPath).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			http.NotFound(w, r)
			return
		}
		logger.ErrorContext(ctx, "Failed to read linter summary from GCS", slog.Any("err", err), slog.String("path", objPath))
		http.Error(w, "Failed to read summary", http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/json")
	if _, err := io.Copy(w, reader); err != nil {
		logger.ErrorContext(ctx, "Failed to stream summary JSON", slog.Any("err", err))
	}
}

