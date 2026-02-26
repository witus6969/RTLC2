package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ===================== Constants =====================

// Valid blob storage categories.
const (
	CategoryPayloads    = "payloads"
	CategoryDownloads   = "downloads"
	CategoryScreenshots = "screenshots"
	CategoryLoot        = "loot"
	CategoryUploads     = "uploads"
)

// validCategories is the set of allowed category names.
var validCategories = map[string]bool{
	CategoryPayloads:    true,
	CategoryDownloads:   true,
	CategoryScreenshots: true,
	CategoryLoot:        true,
	CategoryUploads:     true,
}

// ===================== Data Types =====================

// BlobInfo holds metadata about a stored blob.
type BlobInfo struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	AgentID   string    `json:"agent_id"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// blobMetadata is the internal metadata structure serialized alongside each blob.
type blobMetadata struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	AgentID   string    `json:"agent_id"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	MIMEType  string    `json:"mime_type,omitempty"`
}

// ===================== BlobStore =====================

// BlobStore provides file-based blob storage organized by category and agent.
// Each blob is stored as a data file with a companion JSON metadata file.
//
// Directory layout:
//
//	basePath/
//	  payloads/
//	    <agentID>/
//	      <blobID>_<filename>
//	      <blobID>_<filename>.meta.json
//	  downloads/
//	    ...
type BlobStore struct {
	basePath string
}

// NewBlobStore creates a new BlobStore rooted at basePath and initializes
// the directory structure for all valid categories.
func NewBlobStore(basePath string) (*BlobStore, error) {
	bs := &BlobStore{basePath: basePath}

	// Create the base directory and all category subdirectories.
	for category := range validCategories {
		dir := filepath.Join(basePath, category)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create storage directory %s: %w", dir, err)
		}
	}

	return bs, nil
}

// Store persists a blob under the given category and agent ID.
// It returns a unique blob ID that can be used to retrieve or delete the blob.
func (bs *BlobStore) Store(category, agentID, filename string, data []byte) (string, error) {
	if !validCategories[category] {
		return "", fmt.Errorf("invalid category: %s (valid: %s)", category, validCategoryList())
	}

	if filename == "" {
		return "", fmt.Errorf("filename cannot be empty")
	}

	// Sanitize filename to prevent path traversal.
	filename = filepath.Base(filename)

	// Generate a unique blob ID.
	blobID := uuid.New().String()[:8]

	// Ensure the agent directory exists.
	agentDir := filepath.Join(bs.basePath, category, sanitizePathComponent(agentID))
	if err := os.MkdirAll(agentDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create agent directory: %w", err)
	}

	// Write the blob data file.
	blobFilename := blobID + "_" + filename
	blobPath := filepath.Join(agentDir, blobFilename)
	if err := os.WriteFile(blobPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write blob data: %w", err)
	}

	// Write the metadata sidecar JSON.
	meta := &blobMetadata{
		ID:        blobID,
		Category:  category,
		AgentID:   agentID,
		Filename:  filename,
		Size:      int64(len(data)),
		CreatedAt: time.Now(),
	}

	metaPath := blobPath + ".meta.json"
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		// Clean up the data file on metadata write failure.
		os.Remove(blobPath)
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		os.Remove(blobPath)
		return "", fmt.Errorf("failed to write metadata: %w", err)
	}

	return blobID, nil
}

// Retrieve loads a blob by its ID. It searches all categories and agent directories.
// Returns the blob data, original filename, and any error.
func (bs *BlobStore) Retrieve(blobID string) ([]byte, string, error) {
	if blobID == "" {
		return nil, "", fmt.Errorf("blob ID cannot be empty")
	}

	// Search across all categories and agent directories for the blob.
	blobPath, meta, err := bs.findBlob(blobID)
	if err != nil {
		return nil, "", err
	}

	data, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read blob data: %w", err)
	}

	return data, meta.Filename, nil
}

// List returns metadata for all blobs matching the given category and agent ID.
// Either parameter can be empty to match all values in that dimension.
func (bs *BlobStore) List(category, agentID string) ([]BlobInfo, error) {
	var results []BlobInfo

	categories := []string{category}
	if category == "" {
		categories = make([]string, 0, len(validCategories))
		for c := range validCategories {
			categories = append(categories, c)
		}
	} else if !validCategories[category] {
		return nil, fmt.Errorf("invalid category: %s", category)
	}

	for _, cat := range categories {
		catDir := filepath.Join(bs.basePath, cat)
		if _, err := os.Stat(catDir); os.IsNotExist(err) {
			continue
		}

		agentDirs, err := os.ReadDir(catDir)
		if err != nil {
			continue
		}

		for _, agentEntry := range agentDirs {
			if !agentEntry.IsDir() {
				continue
			}

			// If agentID filter is specified, skip non-matching directories.
			if agentID != "" && agentEntry.Name() != sanitizePathComponent(agentID) {
				continue
			}

			agentPath := filepath.Join(catDir, agentEntry.Name())
			files, err := os.ReadDir(agentPath)
			if err != nil {
				continue
			}

			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".meta.json") {
					continue
				}

				metaPath := filepath.Join(agentPath, f.Name())
				meta, err := bs.readMetadata(metaPath)
				if err != nil {
					continue
				}

				results = append(results, BlobInfo{
					ID:        meta.ID,
					Category:  meta.Category,
					AgentID:   meta.AgentID,
					Filename:  meta.Filename,
					Size:      meta.Size,
					CreatedAt: meta.CreatedAt,
				})
			}
		}
	}

	// Sort by creation time, newest first.
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})

	return results, nil
}

// Delete removes a blob and its metadata by blob ID.
func (bs *BlobStore) Delete(blobID string) error {
	if blobID == "" {
		return fmt.Errorf("blob ID cannot be empty")
	}

	blobPath, _, err := bs.findBlob(blobID)
	if err != nil {
		return err
	}

	metaPath := blobPath + ".meta.json"

	// Remove both files. Metadata removal failure is non-fatal.
	if err := os.Remove(blobPath); err != nil {
		return fmt.Errorf("failed to delete blob: %w", err)
	}
	os.Remove(metaPath)

	return nil
}

// ===================== Internal Helpers =====================

// findBlob searches all categories and agent directories for a blob with the given ID.
// Returns the path to the data file and the parsed metadata.
func (bs *BlobStore) findBlob(blobID string) (string, *blobMetadata, error) {
	prefix := blobID + "_"

	for category := range validCategories {
		catDir := filepath.Join(bs.basePath, category)
		if _, err := os.Stat(catDir); os.IsNotExist(err) {
			continue
		}

		agentDirs, err := os.ReadDir(catDir)
		if err != nil {
			continue
		}

		for _, agentEntry := range agentDirs {
			if !agentEntry.IsDir() {
				continue
			}

			agentPath := filepath.Join(catDir, agentEntry.Name())
			files, err := os.ReadDir(agentPath)
			if err != nil {
				continue
			}

			for _, f := range files {
				if f.IsDir() || strings.HasSuffix(f.Name(), ".meta.json") {
					continue
				}

				if strings.HasPrefix(f.Name(), prefix) {
					blobPath := filepath.Join(agentPath, f.Name())
					metaPath := blobPath + ".meta.json"

					meta, err := bs.readMetadata(metaPath)
					if err != nil {
						// Metadata missing or corrupt; reconstruct minimal metadata.
						info, _ := f.Info()
						var size int64
						if info != nil {
							size = info.Size()
						}
						meta = &blobMetadata{
							ID:        blobID,
							Category:  category,
							AgentID:   agentEntry.Name(),
							Filename:  strings.TrimPrefix(f.Name(), prefix),
							Size:      size,
							CreatedAt: time.Now(),
						}
					}

					return blobPath, meta, nil
				}
			}
		}
	}

	return "", nil, fmt.Errorf("blob not found: %s", blobID)
}

// readMetadata reads and parses a metadata JSON sidecar file.
func (bs *BlobStore) readMetadata(path string) (*blobMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var meta blobMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// sanitizePathComponent removes path separators and parent directory references
// from a string intended to be used as a single path component.
func sanitizePathComponent(s string) string {
	if s == "" {
		return "_default"
	}
	// Remove any path separators and dangerous sequences.
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, "..", "_")
	return s
}

// validCategoryList returns a comma-separated string of valid category names.
func validCategoryList() string {
	categories := make([]string, 0, len(validCategories))
	for c := range validCategories {
		categories = append(categories, c)
	}
	sort.Strings(categories)
	return strings.Join(categories, ", ")
}
