package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"github.com/codeGROOVE-dev/fido"
	"github.com/codeGROOVE-dev/fido/pkg/store/cloudrun"
	"github.com/codeGROOVE-dev/fido/pkg/store/null"
	"github.com/codeGROOVE-dev/retry"
)

var (
	uploadTemplate  *template.Template
	resultTemplate  *template.Template
	gcsBucket       string
	cleavePath      string
	cleaveAddr      string       // Address of cleave server (e.g., "127.0.0.1:8080")
	cleaveServerCmd *exec.Cmd    // Managed cleave server process (if we started it)
	cleaveClient    *http.Client // HTTP client for cleave server
	traitsPath      string
	thirdPartyPath  string
	radare2Path     string
	rizinPath       string
	radareCmd       string          // resolved backend: "radare2" or "rizin"
	radareCmdPath   string          // resolved full path to backend
	gcsClient       *storage.Client // reusable GCS client
	cache           *fido.TieredCache[string, storedResult]
	logger          *slog.Logger
)

// FindingDisplay represents a single finding for table display.
type FindingDisplay struct {
	ID       string
	Crit     string
	Desc     string
	Evidence []string
}

// CategoryGroup groups findings by top-level category.
type CategoryGroup struct {
	Name     string // "Objectives", "Micro-behaviors", etc.
	Findings []FindingDisplay
}

// FileFindingsDisplay represents all findings for a single file.
type FileFindingsDisplay struct {
	Path       string
	Basename   string
	Risk       string
	SHA256     string
	Formula    string
	Categories []CategoryGroup
}

// FileStringsDisplay represents strings for a single file.
type FileStringsDisplay struct {
	Basename string
	Risk     string
	SHA256   string
	Formula  string
	Strings  []StringDisplay
}

type StringDisplay struct {
	Value   string
	Section string
}

// FileSymbolsDisplay represents symbols for a single file.
type FileSymbolsDisplay struct {
	Basename string
	Risk     string
	SHA256   string
	Formula  string
	Imports  []SymbolDisplay
	Exports  []SymbolDisplay
}

type SymbolDisplay struct {
	Name    string
	Library string
}

// FileSectionsDisplay represents sections for a single file.
type FileSectionsDisplay struct {
	Basename string
	Risk     string
	SHA256   string
	Formula  string
	Sections []SectionDisplay
}

type SectionDisplay struct {
	Name    string
	Size    int64
	Entropy float64
	Flags   string
}

// FileMetricsDisplay represents metrics for a single file.
type FileMetricsDisplay struct {
	Basename       string
	Risk           string
	SHA256         string
	Formula        string
	FileSize       int64
	CodeSize       int64
	OverallEntropy float64
	CodeEntropy    float64
}

type resultData struct {
	Filename     string
	SHA256       string
	SHA256Short  string
	Formula      template.HTML
	FileType     string
	RiskLevel    string // "hostile", "suspicious", "notable", or ""
	RiskLabel    string
	Verdict      string // "HOSTILE", "SUSPICIOUS", "NOTABLE", or "BASELINE"
	Size         string
	FindingCount string
	Duration     string
	MoleculeJSON template.JS
	// Structured data for table display
	FileFindings []FileFindingsDisplay
	FileStrings  []FileStringsDisplay
	FileSymbols  []FileSymbolsDisplay
	FileSections []FileSectionsDisplay
	FileMetrics  []FileMetricsDisplay
}

// storedResult is what we persist in fido/datastore
type storedResult struct {
	Filename string
	JSON     string
	Traits   string
	Strings  string
	Symbols  string
	Sections string
	Metrics  string
}

// cleaveError represents an error from cleave that shouldn't be cached
// but should still be displayed to the user
type cleaveError struct {
	filename string
	output   string
}

func (e *cleaveError) Error() string {
	return "cleave returned an error"
}

// cleaveReport is constructed from JSONL output (multiple lines)
type cleaveReport struct {
	Files   []cleaveFile
	Summary *cleaveSummary
}

// cleaveJSONLEntry represents a single line in JSONL output
type cleaveJSONLEntry struct {
	Type string `json:"type"` // "file" or "summary"

	// File entry fields
	ID       int            `json:"id"`
	Path     string         `json:"path"`
	Depth    int            `json:"depth"`
	FileType string         `json:"file_type"`
	SHA256   string         `json:"sha256"`
	Size     int64          `json:"size"`
	Risk     string         `json:"risk,omitempty"`
	Counts   *findingCounts `json:"counts,omitempty"`
	Findings []finding      `json:"findings,omitempty"`
	Strings  []stringInfo   `json:"strings,omitempty"`
	Imports  []symbolInfo   `json:"imports,omitempty"`
	Exports  []symbolInfo   `json:"exports,omitempty"`
	Sections []sectionInfo  `json:"sections,omitempty"`
	Metrics  *metricsInfo   `json:"metrics,omitempty"`
	Formula  string         `json:"formula,omitempty"`

	// Summary entry fields
	FilesAnalyzed      int   `json:"files_analyzed,omitempty"`
	Hostile            int   `json:"hostile,omitempty"`
	Suspicious         int   `json:"suspicious,omitempty"`
	Notable            int   `json:"notable,omitempty"`
	AnalysisDurationMs int64 `json:"analysis_duration_ms,omitempty"`
}

type cleaveFile struct {
	ID       int            `json:"id"`
	Path     string         `json:"path"`
	Depth    int            `json:"depth"`
	FileType string         `json:"file_type"`
	SHA256   string         `json:"sha256"`
	Size     int64          `json:"size"`
	Risk     string         `json:"risk,omitempty"`
	Counts   *findingCounts `json:"counts,omitempty"`
	Findings []finding      `json:"findings"`
	Strings  []stringInfo   `json:"strings,omitempty"`
	Imports  []symbolInfo   `json:"imports,omitempty"`
	Exports  []symbolInfo   `json:"exports,omitempty"`
	Sections []sectionInfo  `json:"sections,omitempty"`
	Metrics  *metricsInfo   `json:"metrics,omitempty"`
	Formula  string         `json:"formula,omitempty"`
}

type stringInfo struct {
	Value    string `json:"value"`
	Offset   string `json:"offset,omitempty"`
	Section  string `json:"section,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type symbolInfo struct {
	Symbol  string `json:"symbol"`
	Name    string `json:"name,omitempty"`
	Source  string `json:"source,omitempty"`
	Address string `json:"address,omitempty"`
	Type    string `json:"type,omitempty"`
	Library string `json:"library,omitempty"`
}

type sectionInfo struct {
	Name    string      `json:"name"`
	Address interface{} `json:"address,omitempty"` // Can be string or number
	Size    int64       `json:"size"`
	Entropy float64     `json:"entropy,omitempty"`
	Flags   string      `json:"flags,omitempty"`
}

type metricsInfo struct {
	Binary *binaryMetrics `json:"binary,omitempty"`
}

type binaryMetrics struct {
	FileSize        int64   `json:"file_size"`
	CodeSize        int64   `json:"code_size,omitempty"`
	OverallEntropy  float64 `json:"overall_entropy,omitempty"`
	CodeEntropy     float64 `json:"code_entropy,omitempty"`
	SectionCount    int     `json:"section_count,omitempty"`
	ImportCount     int     `json:"import_count,omitempty"`
	ExportCount     int     `json:"export_count,omitempty"`
	StringCount     int     `json:"string_count,omitempty"`
	FunctionCount   int     `json:"function_count,omitempty"`
	AvgComplexity   float64 `json:"avg_complexity,omitempty"`
	IsPIE           bool    `json:"is_pie,omitempty"`
	CodeToDataRatio float64 `json:"code_to_data_ratio,omitempty"`
}

type findingCounts struct {
	Hostile    int `json:"hostile"`
	Suspicious int `json:"suspicious"`
	Notable    int `json:"notable"`
}

type finding struct {
	ID       string     `json:"id"`
	Desc     string     `json:"desc"`
	Crit     string     `json:"crit,omitempty"` // optional - defaults to neutral
	Conf     float64    `json:"conf"`
	Kind     string     `json:"kind,omitempty"` // "structural" for internal symbols
	Evidence []evidence `json:"evidence,omitempty"`
}

type evidence struct {
	Value string `json:"value"`
}

type cleaveSummary struct {
	FilesAnalyzed      int   `json:"files_analyzed"`
	Hostile            int   `json:"hostile"`
	Suspicious         int   `json:"suspicious"`
	Notable            int   `json:"notable"`
	AnalysisDurationMs int64 `json:"analysis_duration_ms"`
}

// moleculeAtom for 3D visualization
type moleculeAtom struct {
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Z        float64 `json:"z"`
	Radius   float64 `json:"radius"`
	Severity string  `json:"severity"`
	ID       string  `json:"id"`
}

type moleculeData struct {
	Atoms []moleculeAtom `json:"atoms"`
	Bonds [][2]int       `json:"bonds"`
}

// toolInfo holds information about an external tool.
type toolInfo struct {
	name    string
	path    string
	version string
}

func init() {
	// Initialize structured logger with JSON output for production
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)
}

func main() {
	// Parse command-line flags
	flushCache := false
	noCache := false
	for i, arg := range os.Args[1:] {
		switch {
		case arg == "--flush" || arg == "-flush":
			flushCache = true
		case arg == "--no-cache" || arg == "-no-cache":
			noCache = true
		case strings.HasPrefix(arg, "--cleave-addr="):
			cleaveAddr = strings.TrimPrefix(arg, "--cleave-addr=")
		case arg == "--cleave-addr" && i+1 < len(os.Args[1:]):
			cleaveAddr = os.Args[i+2]
		}
	}

	logger.Info("web-flayer starting",
		"go_version", runtime.Version(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"pid", os.Getpid(),
	)

	ctx := context.Background()

	// Load configuration from environment
	if err := loadConfig(); err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Validate required external tools
	if err := validateTools(); err != nil {
		logger.Error("tool validation failed", "error", err)
		os.Exit(1)
	}

	// Initialize fido cache
	var cacheErr error
	if noCache {
		// Use null store for local development (no caching)
		logger.Info("cache disabled via --no-cache flag, using null store")
		nullStore := null.New[string, storedResult]()
		cache, cacheErr = fido.NewTiered(nullStore)
		if cacheErr != nil {
			logger.Error("failed to initialize fido tiered cache", "error", cacheErr)
			os.Exit(1)
		}
	} else {
		// Use Cloud Run auto-detection for production
		logger.Debug("initializing fido store", "cache_id", "divine")
		store, storeErr := cloudrun.New[string, storedResult](ctx, "divine")
		if storeErr != nil {
			logger.Error("failed to initialize fido store", "error", storeErr)
			os.Exit(1)
		}
		cache, cacheErr = fido.NewTiered(store)
		if cacheErr != nil {
			logger.Error("failed to initialize fido tiered cache", "error", cacheErr)
			os.Exit(1)
		}

		// Handle --flush command (only relevant when using real cache)
		if flushCache {
			logger.Info("flushing in-memory cache")
			if closeErr := cache.Close(); closeErr != nil {
				logger.Warn("error closing cache", "error", closeErr)
			}
			cache, cacheErr = fido.NewTiered(store)
			if cacheErr != nil {
				logger.Error("failed to reinitialize cache", "error", cacheErr)
				os.Exit(1)
			}
			logger.Info("in-memory cache flushed successfully")
			fmt.Println("In-memory cache cleared. Note: Persistent cache in datastore is not affected.")
			fmt.Println("For full cache clear, delete entries from your datastore.")
			os.Exit(0)
		}
	}

	// Parse templates
	if err := loadTemplates(); err != nil {
		logger.Error("template loading failed", "error", err)
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/upload", handleUpload)
	mux.HandleFunc("/file/", handleFile)
	mux.HandleFunc("/health", handleHealth)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 150 * time.Second, // 120s analysis + buffer
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("shutdown signal received", "signal", sig.String())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}

		// Close GCS client if initialized
		if gcsClient != nil {
			if err := gcsClient.Close(); err != nil {
				logger.Error("failed to close GCS client", "error", err)
			}
		}

		if cache != nil {
			if err := cache.Close(); err != nil {
				logger.Error("failed to close fido cache", "error", err)
			}
		}

		// Stop managed cleave server if we started it
		stopCleaveServer()

		close(done)
	}()

	logger.Info("server starting",
		"port", port,
		"cleave_addr", cleaveAddr,
		"traits_path", traitsPath,
		"radare_backend", radareCmd,
		"radare_path", radareCmdPath,
		"gcs_bucket", gcsBucket,
	)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	<-done
	logger.Info("server stopped")
}

// loadConfig loads configuration from environment variables.
func loadConfig() error {
	gcsBucket = os.Getenv("GCS_BUCKET")
	cleavePath = os.Getenv("CLEAVE_PATH")
	traitsPath = os.Getenv("CLEAVE_TRAITS_DIR")
	thirdPartyPath = os.Getenv("CLEAVE_3P_DIR")
	radare2Path = os.Getenv("RADARE2_PATH")
	rizinPath = os.Getenv("RIZIN_PATH")

	// CLEAVE_ADDR from env (flag takes precedence)
	if cleaveAddr == "" {
		cleaveAddr = os.Getenv("CLEAVE_ADDR")
	}

	if cleavePath == "" {
		cleavePath = "cleave"
	}
	if radare2Path == "" {
		radare2Path = "radare2"
	}
	if rizinPath == "" {
		rizinPath = "rizin"
	}

	// Auto-discover traits directory if not set
	if traitsPath == "" {
		candidates := []string{
			"traits",
			"../cleave/traits",
		}
		cwd, _ := os.Getwd()
		logger.Debug("auto-discovering traits directory", "cwd", cwd, "candidates", candidates)
		for _, candidate := range candidates {
			absCandidate, _ := filepath.Abs(candidate)
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				traitsPath = absCandidate
				logger.Info("auto-discovered traits directory", "path", traitsPath, "candidate", candidate)
				break
			} else {
				logger.Debug("traits candidate not found", "candidate", candidate, "abs_path", absCandidate, "error", err)
			}
		}
		if traitsPath == "" {
			logger.Warn("no traits directory found - cleave will fail unless CLEAVE_TRAITS_DIR is set")
		}
	} else {
		logger.Info("using configured traits directory", "path", traitsPath)
	}

	// Auto-discover third-party directory if not set
	if thirdPartyPath == "" {
		candidates := []string{
			"third_party",
			"../cleave/third_party",
		}
		for _, candidate := range candidates {
			absCandidate, _ := filepath.Abs(candidate)
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				thirdPartyPath = absCandidate
				logger.Info("auto-discovered third-party directory", "path", thirdPartyPath, "candidate", candidate)
				break
			}
		}
	} else {
		logger.Info("using configured third-party directory", "path", thirdPartyPath)
	}

	logger.Debug("configuration loaded",
		"CLEAVE_PATH", cleavePath,
		"CLEAVE_ADDR", cleaveAddr,
		"CLEAVE_TRAITS_DIR", traitsPath,
		"CLEAVE_3P_DIR", thirdPartyPath,
		"RADARE2_PATH", radare2Path,
		"RIZIN_PATH", rizinPath,
		"GCS_BUCKET", gcsBucket,
		"PORT", os.Getenv("PORT"),
	)

	return nil
}

// validateTools checks that all required external tools are available.
func validateTools() error {
	var errs []error

	// Initialize cleave server (connect to existing or start new)
	if err := initCleaveServer(); err != nil {
		errs = append(errs, fmt.Errorf("cleave server: %w", err))
	}

	// Validate radare2 or rizin (flayer requires one of these)
	radareInfo, err := validateRadare()
	if err != nil {
		errs = append(errs, fmt.Errorf("radare2/rizin: %w (set RADARE2_PATH or RIZIN_PATH to specify location)", err))
	} else {
		radareCmd = radareInfo.name
		radareCmdPath = radareInfo.path
		logger.Info("radare backend validated",
			"backend", radareInfo.name,
			"path", radareInfo.path,
			"version", radareInfo.version,
		)
	}

	// Validate traits path if specified (optional for cleave)
	if traitsPath != "" {
		if info, err := os.Stat(traitsPath); err != nil {
			logger.Warn("traits path not found", "path", traitsPath, "error", err)
		} else if !info.IsDir() {
			logger.Warn("traits path is not a directory", "path", traitsPath)
		} else {
			traitCount, traitErr := countTraitFiles(traitsPath)
			if traitErr != nil {
				logger.Warn("failed to scan traits path", "path", traitsPath, "error", traitErr)
			} else {
				logger.Info("traits path validated",
					"path", traitsPath,
					"trait_files", traitCount,
				)
			}
		}
	}

	// Validate GCS bucket if configured
	if gcsBucket != "" {
		if err := initGCSClient(); err != nil {
			errs = append(errs, fmt.Errorf("GCS client: %w", err))
		} else if err := validateGCSBucket(gcsBucket); err != nil {
			errs = append(errs, fmt.Errorf("GCS bucket %q: %w", gcsBucket, err))
		} else {
			logger.Info("GCS bucket validated",
				"bucket", gcsBucket,
			)
		}
	} else {
		logger.Debug("no GCS bucket configured, file archiving disabled")
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// validateTool checks if a tool exists and is executable.
func validateTool(name, path, versionFlag string) (*toolInfo, error) {
	// Resolve the full path
	resolvedPath, err := exec.LookPath(path)
	if err != nil {
		return nil, fmt.Errorf("not found in PATH: %w", err)
	}

	logger.Debug("tool path resolved",
		"name", name,
		"configured_path", path,
		"resolved_path", resolvedPath,
	)

	// Check it's executable
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat %q: %w", resolvedPath, err)
	}

	if info.Mode()&0111 == 0 {
		return nil, fmt.Errorf("%q is not executable", resolvedPath)
	}

	// Get version info
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolvedPath, versionFlag)
	output, err := cmd.CombinedOutput()
	version := strings.TrimSpace(string(output))
	if err != nil {
		logger.Warn("failed to get tool version",
			"name", name,
			"path", resolvedPath,
			"error", err,
			"output", version,
		)
		version = "unknown"
	}

	return &toolInfo{
		name:    name,
		path:    resolvedPath,
		version: version,
	}, nil
}

// countTraitFiles counts .yaml files recursively in a directory.
func countTraitFiles(dir string) (int, error) {
	count := 0
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".yaml") {
			count++
		}
		return nil
	})
	return count, err
}

// initGCSClient initializes the reusable GCS client.
func initGCSClient() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger.Debug("initializing GCS client")

	var err error
	gcsClient, err = storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create storage client: %w", err)
	}

	return nil
}

// validateGCSBucket checks that the GCS bucket exists and is accessible.
func validateGCSBucket(bucket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger.Debug("validating GCS bucket connectivity",
		"bucket", bucket,
	)

	if gcsClient == nil {
		return fmt.Errorf("GCS client not initialized")
	}

	// Check bucket exists and we have access
	_, err := gcsClient.Bucket(bucket).Attrs(ctx)
	if err != nil {
		return fmt.Errorf("failed to access bucket: %w", err)
	}

	return nil
}

// validateRadare checks for radare2 or rizin (fallback).
func validateRadare() (*toolInfo, error) {
	var radare2Err, rizinErr error

	// Try radare2 first
	if info, err := validateTool("radare2", radare2Path, "-v"); err == nil {
		return info, nil
	} else {
		radare2Err = err
		logger.Debug("radare2 not available",
			"configured_path", radare2Path,
			"error", err,
		)
	}

	// Fall back to rizin
	if info, err := validateTool("rizin", rizinPath, "-v"); err == nil {
		return info, nil
	} else {
		rizinErr = err
		logger.Debug("rizin not available",
			"configured_path", rizinPath,
			"error", err,
		)
	}

	return nil, fmt.Errorf("neither radare2 nor rizin found (radare2: %v; rizin: %v); set RADARE2_PATH or RIZIN_PATH", radare2Err, rizinErr)
}

// loadTemplates parses the HTML templates.
func loadTemplates() error {
	templateDir := "templates"

	// Check if templates directory exists
	if info, err := os.Stat(templateDir); err != nil {
		return fmt.Errorf("templates directory: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("templates path is not a directory: %s", templateDir)
	}

	var err error
	uploadTemplate, err = template.ParseFiles(filepath.Join(templateDir, "upload.html"))
	if err != nil {
		return fmt.Errorf("parse upload.html: %w", err)
	}

	// Template functions for calculations
	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}
	resultTemplate, err = template.New("result.html").Funcs(funcMap).ParseFiles(filepath.Join(templateDir, "result.html"))
	if err != nil {
		return fmt.Errorf("parse result.html: %w", err)
	}

	logger.Debug("templates loaded",
		"upload_template", "templates/upload.html",
		"result_template", "templates/result.html",
	)

	return nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := uploadTemplate.Execute(w, nil); err != nil {
		logger.Error("template execution failed",
			"template", "upload",
			"error", err,
		)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK\n")); err != nil {
		logger.Debug("health check write failed", "error", err)
	}
}

func handleFile(w http.ResponseWriter, r *http.Request) {
	sha := strings.TrimPrefix(r.URL.Path, "/file/")
	if sha == "" {
		http.Error(w, "Missing SHA256", http.StatusBadRequest)
		return
	}

	reqLogger := logger.With("sha256", sha)
	reqLogger.Debug("file request received")

	// Use Fetch to deduplicate concurrent loads and provide a potential fallback
	res, err := cache.Fetch(r.Context(), sha, func(lctx context.Context) (storedResult, error) {
		// Fallback: If not in cache, check GCS if configured
		if gcsBucket == "" || gcsClient == nil {
			reqLogger.Debug("cache miss, GCS not configured for fallback")
			return storedResult{}, errors.New("result not in cache and GCS not configured")
		}

		reqLogger.Info("cache miss, attempting fallback to GCS")

		// Find the file in GCS. Since filename is part of path, we need to list or know it.
		it := gcsClient.Bucket(gcsBucket).Objects(lctx, &storage.Query{Prefix: sha + "/"})
		attrs, err := it.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				reqLogger.Debug("file not found in GCS", "prefix", sha+"/")
				return storedResult{}, errors.New("file not found in GCS")
			}
			reqLogger.Error("GCS list failed", "error", err)
			return storedResult{}, fmt.Errorf("GCS list failed: %w", err)
		}

		filename := filepath.Base(attrs.Name)
		reqLogger.Info("found file in GCS, re-analyzing", "filename", filename, "gcs_path", attrs.Name)

		// Download from GCS to temp file
		tempFile, err := os.CreateTemp("", "cleave-fallback-*")
		if err != nil {
			return storedResult{}, fmt.Errorf("failed to create temp file: %w", err)
		}
		tempPath := tempFile.Name()
		defer os.Remove(tempPath)
		defer tempFile.Close()

		reqLogger.Debug("downloading from GCS", "temp_path", tempPath)
		rc, err := gcsClient.Bucket(gcsBucket).Object(attrs.Name).NewReader(lctx)
		if err != nil {
			return storedResult{}, fmt.Errorf("GCS reader failed: %w", err)
		}
		defer rc.Close()

		dlStart := time.Now()
		if _, err := io.Copy(tempFile, rc); err != nil {
			return storedResult{}, fmt.Errorf("failed to download from GCS: %w", err)
		}
		reqLogger.Debug("GCS download complete", "duration_ms", time.Since(dlStart).Milliseconds())
		tempFile.Close()

		// Run analysis
		reqLogger.Debug("starting fallback analysis")
		cleaveRes, err := runCleave(lctx, tempPath, reqLogger)
		if err != nil {
			return storedResult{}, fmt.Errorf("cleave failed: %w", err)
		}

		return storedResult{
			Filename: filename,
			JSON:     cleaveRes.JSON,
			Traits:   cleaveRes.Traits,
			Strings:  cleaveRes.Strings,
			Symbols:  cleaveRes.Symbols,
			Sections: cleaveRes.Sections,
			Metrics:  cleaveRes.Metrics,
		}, nil
	})

	if err != nil {
		reqLogger.Warn("failed to retrieve or regenerate result", "error", err)
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "Result not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to retrieve result", http.StatusInternalServerError)
		}
		return
	}

	reqLogger.Debug("rendering result", "filename", res.Filename)
	data := prepareResultData(res.Filename, sha, &res)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := resultTemplate.Execute(w, data); err != nil {
		reqLogger.Error("template execution failed",
			"template", "result",
			"error", err,
		)
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())

	reqLogger := logger.With(
		"request_id", requestID,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)

	reqLogger.Info("upload request received")

	if r.Method != http.MethodPost {
		reqLogger.Warn("invalid method", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	reqLogger.Debug("parsing multipart form", "max_memory", "100MB")
	if err := r.ParseMultipartForm(100 * 1024 * 1024); err != nil {
		reqLogger.Error("failed to parse multipart form", "error", err)
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		reqLogger.Error("failed to read uploaded file", "error", err)
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(fileHeader.Filename)
	reqLogger = reqLogger.With("filename", filename, "size", fileHeader.Size)
	reqLogger.Info("file received")

	// Preserve file extension for cleave to detect archive types
	ext := filepath.Ext(filename)
	tempPattern := "cleave-*"
	if ext != "" {
		tempPattern = "cleave-*" + ext
	}
	tempFile, err := os.CreateTemp("", tempPattern)
	if err != nil {
		reqLogger.Error("failed to create temp file", "error", err)
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		return
	}
	tempPath := tempFile.Name()

	// Use WaitGroup to coordinate cleanup across background tasks
	var cleanupWg sync.WaitGroup
	cleanupWg.Add(2) // GCS upload + Analysis task

	go func() {
		reqLogger.Debug("waiting for cleanup tasks to complete", "path", tempPath)
		cleanupWg.Wait()
		if err := os.Remove(tempPath); err != nil {
			reqLogger.Debug("failed to remove temp file", "path", tempPath, "error", err)
		} else {
			reqLogger.Debug("temp file removed successfully", "path", tempPath)
		}
	}()

	reqLogger.Debug("temp file created", "path", tempPath)

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(tempFile, hash), file)
	if err != nil {
		tempFile.Close()
		os.Remove(tempPath)
		reqLogger.Error("failed to write temp file", "error", err, "bytes_written", written)
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}
	tempFile.Close()

	sha256Hex := fmt.Sprintf("%x", hash.Sum(nil))
	reqLogger = reqLogger.With("sha256", sha256Hex)
	reqLogger.Info("file written to temp", "bytes", written)

	// Upload to GCS if configured (background, simultaneous to analysis)
	if gcsBucket != "" && gcsClient != nil {
		go func() {
			defer cleanupWg.Done()
			reqLogger.Debug("starting background GCS upload")
			// Use a background context that isn't tied to the request lifecycle
			// so the upload can continue after the redirect.
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			f, err := os.Open(tempPath)
			if err != nil {
				reqLogger.Error("failed to open temp file for background GCS upload", "error", err)
				return
			}
			defer f.Close()

			if err := uploadToGCS(bgCtx, gcsBucket, sha256Hex, filename, f, reqLogger); err != nil {
				reqLogger.Error("background GCS upload failed", "error", err)
			}
		}()
	} else {
		reqLogger.Debug("skipping GCS upload (not configured)")
		cleanupWg.Done()
	}

	// Run cleave analysis via fido.Fetch to deduplicate concurrent requests
	// With --no-cache, uses null store which doesn't persist but still deduplicates
	reqLogger.Info("starting/joining analysis fetch", "sha256", sha256Hex, "filename", filename)
	fetchStart := time.Now()
	res, err := cache.Fetch(ctx, sha256Hex, func(_ context.Context) (storedResult, error) {
		defer cleanupWg.Done()

		reqLogger.Info("cache miss, executing new analysis", "sha256", sha256Hex)
		lctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		analysisStart := time.Now()
		cleaveRes, runErr := runCleave(lctx, tempPath, reqLogger)
		analysisDuration := time.Since(analysisStart)

		if runErr != nil {
			reqLogger.Error("cleave analysis failed",
				"error", runErr,
				"duration_ms", analysisDuration.Milliseconds(),
			)
			return storedResult{}, fmt.Errorf("cleave run error: %w", runErr)
		}

		// Check if cleave output contains errors (don't cache these)
		if strings.Contains(cleaveRes.JSON, "Error:") || strings.Contains(cleaveRes.Traits, "Error:") {
			reqLogger.Warn("cleave output contains errors, not caching",
				"duration_ms", analysisDuration.Milliseconds(),
			)
			return storedResult{}, &cleaveError{
				filename: filename,
				output:   cleaveRes.Traits,
			}
		}

		reqLogger.Info("cleave analysis completed",
			"duration_ms", analysisDuration.Milliseconds(),
		)

		return storedResult{
			Filename: filename,
			JSON:     cleaveRes.JSON,
			Traits:   cleaveRes.Traits,
			Strings:  cleaveRes.Strings,
			Symbols:  cleaveRes.Symbols,
			Sections: cleaveRes.Sections,
			Metrics:  cleaveRes.Metrics,
		}, nil
	})

	fetchDuration := time.Since(fetchStart)
	if err != nil {
		// Check if it's a cleaveError - these are displayable but not cached
		var ce *cleaveError
		if errors.As(err, &ce) {
			reqLogger.Warn("cleave returned error (not cached)",
				"fetch_duration_ms", fetchDuration.Milliseconds(),
			)
			// Create a minimal result to display the error
			res = storedResult{
				Filename: ce.filename,
				Traits:   ce.output,
			}
		} else {
			reqLogger.Error("analysis fetch failed", "error", err, "fetch_duration_ms", fetchDuration.Milliseconds())
			http.Error(w, "Analysis failed", http.StatusInternalServerError)
			return
		}
	}

	reqLogger.Info("request completed, redirecting to result",
		"total_duration_ms", time.Since(requestStart).Milliseconds(),
		"fetch_duration_ms", fetchDuration.Milliseconds(),
		"cached_filename", res.Filename,
		"json_bytes", len(res.JSON),
		"traits_bytes", len(res.Traits),
	)

	http.Redirect(w, r, "/file/"+sha256Hex, http.StatusSeeOther)
}

// parseJSONL parses cleave's JSONL output into a cleaveReport.
func parseJSONL(rawJSON string) (*cleaveReport, error) {
	report := &cleaveReport{}

	lines := strings.Split(rawJSON, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry cleaveJSONLEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			logger.Debug("failed to parse JSONL line", "error", err, "line", line[:min(len(line), 100)])
			continue
		}

		switch entry.Type {
		case "file":
			report.Files = append(report.Files, cleaveFile{
				ID:       entry.ID,
				Path:     entry.Path,
				Depth:    entry.Depth,
				FileType: entry.FileType,
				SHA256:   entry.SHA256,
				Size:     entry.Size,
				Risk:     entry.Risk,
				Counts:   entry.Counts,
				Findings: entry.Findings,
				Strings:  entry.Strings,
				Imports:  entry.Imports,
				Exports:  entry.Exports,
				Sections: entry.Sections,
				Metrics:  entry.Metrics,
				Formula:  entry.Formula,
			})
		case "summary":
			report.Summary = &cleaveSummary{
				FilesAnalyzed:      entry.FilesAnalyzed,
				Hostile:            entry.Hostile,
				Suspicious:         entry.Suspicious,
				Notable:            entry.Notable,
				AnalysisDurationMs: entry.AnalysisDurationMs,
			}
		}
	}

	return report, nil
}

// prepareResultData converts raw cleave output to template data.
func prepareResultData(filename, sha256Hex string, res *storedResult) resultData {
	data := resultData{
		Filename:     html.EscapeString(filename),
		SHA256:       sha256Hex,
		SHA256Short:  sha256Hex[:12] + "...",
		FileType:     "UNKNOWN",
		RiskLevel:    "",
		RiskLabel:    "",
		Size:         "0 B",
		FindingCount: "0",
		Duration:     "0ms",
		MoleculeJSON: template.JS("{}"),
	}

	if sha256Hex != "" && len(sha256Hex) >= 12 {
		data.SHA256Short = sha256Hex[:12] + "..."
	}

	// Parse JSONL to extract metadata and findings
	report, err := parseJSONL(res.JSON)
	if err != nil || (len(report.Files) == 0 && report.Summary == nil) {
		logger.Debug("failed to parse cleave JSONL", "error", err)
		data.Formula = template.HTML("?")
		return data
	}

	// Extract target info from top-level file (depth=0) or first file
	for _, file := range report.Files {
		if file.Depth == 0 {
			data.FileType = strings.ToUpper(file.FileType)
			data.Size = formatBytes(file.Size)
			break
		}
	}
	// Fallback to first file if no depth=0 found
	if data.FileType == "" && len(report.Files) > 0 {
		data.FileType = strings.ToUpper(report.Files[0].FileType)
		data.Size = formatBytes(report.Files[0].Size)
	}

	// Extract duration from summary
	if report.Summary != nil {
		data.Duration = fmt.Sprintf("%dms", report.Summary.AnalysisDurationMs)
	}

	// Extract findings for formula generation (skip structural/internal findings)
	var findings []FindingForFormula
	var totalFindings int

	for _, file := range report.Files {
		for _, f := range file.Findings {
			// Skip structural/internal symbols - they clutter the formula
			if f.Kind == "structural" || strings.HasPrefix(f.ID, "metadata/internal/") {
				continue
			}
			totalFindings++
			findings = append(findings, FindingForFormula{
				ID:       f.ID,
				Severity: critToSeverity(f.Crit),
			})
		}
	}

	data.FindingCount = fmt.Sprintf("%d", totalFindings)

	// Determine max risk from summary or calculate from findings
	if report.Summary != nil {
		if report.Summary.Hostile > 0 {
			data.RiskLevel = "hostile"
			data.RiskLabel = "Hostile"
		} else if report.Summary.Suspicious > 0 {
			data.RiskLevel = "suspicious"
			data.RiskLabel = "Suspicious"
		} else if report.Summary.Notable > 0 {
			data.RiskLevel = "notable"
			data.RiskLabel = "Notable"
		}
	} else if len(findings) > 0 {
		maxSev := SeverityNeutral
		for _, f := range findings {
			if f.Severity > maxSev {
				maxSev = f.Severity
			}
		}
		if maxSev > SeverityNeutral {
			data.RiskLevel = maxSev.String()
			data.RiskLabel = strings.Title(maxSev.String())
		}
	}

	// Build structured data for table display
	data.FileFindings = buildStructuredFindings(report.Files)
	data.FileStrings = buildStructuredStrings(report.Files)
	data.FileSymbols = buildStructuredSymbols(report.Files)
	data.FileSections = buildStructuredSections(report.Files)
	data.FileMetrics = buildStructuredMetrics(report.Files)

	// Set verdict based on highest criticality found in structured findings
	data.Verdict = "BASELINE"
	for _, ff := range data.FileFindings {
		switch ff.Risk {
		case "hostile":
			data.Verdict = "HOSTILE"
		case "suspicious":
			if data.Verdict != "HOSTILE" {
				data.Verdict = "SUSPICIOUS"
			}
		case "notable":
			if data.Verdict != "HOSTILE" && data.Verdict != "SUSPICIOUS" {
				data.Verdict = "NOTABLE"
			}
		}
	}

	// Use formula from cleave with file type prefix
	// For archives, find the top-level entry (Depth == 0)
	formula := ""
	for _, file := range report.Files {
		if file.Depth == 0 {
			formula = formatFormula(file.FileType, file.Formula)
			break
		}
	}
	// Fallback to first file if no depth=0 found
	if formula == "" && len(report.Files) > 0 {
		formula = formatFormula(report.Files[0].FileType, report.Files[0].Formula)
	}
	if formula == "" {
		formula = "∅" // Empty set for no findings
	}
	data.Formula = template.HTML(html.EscapeString(formula))

	// Generate molecule/galaxy data for 3D visualization
	// For archives with multiple files, build a galaxy
	if len(report.Files) > 1 {
		var fileFindings []FileFindings
		for _, file := range report.Files {
			var ff []FindingForFormula
			for _, f := range file.Findings {
				if f.Kind == "structural" || strings.HasPrefix(f.ID, "metadata/internal/") {
					continue
				}
				ff = append(ff, FindingForFormula{
					ID:       f.ID,
					Severity: critToSeverity(f.Crit),
				})
			}

			// Extract string values for dropper detection
			var strs []string
			for _, s := range file.Strings {
				strs = append(strs, s.Value)
			}

			// Also scan evidence for dropper detection (may contain file references)
			for _, f := range file.Findings {
				for _, e := range f.Evidence {
					strs = append(strs, e.Value)
				}
			}

			if len(ff) > 0 {
				fileFindings = append(fileFindings, FileFindings{
					Path:     file.Path,
					Risk:     file.Risk,
					Formula:  file.Formula,
					Findings: ff,
					Strings:  strs,
				})
			}
		}

		galaxy := BuildGalaxy(fileFindings)
		galaxyJSON, err := json.Marshal(galaxy)
		if err != nil {
			logger.Debug("failed to marshal galaxy data", "error", err)
			data.MoleculeJSON = template.JS("{}")
		} else {
			data.MoleculeJSON = template.JS(galaxyJSON)
		}

	} else {
		// Single file - build single molecule
		mol := BuildMalecule(findings, formula)
		molJSON, err := json.Marshal(mol)
		if err != nil {
			logger.Debug("failed to marshal molecule data", "error", err)
			data.MoleculeJSON = template.JS("{}")
		} else {
			data.MoleculeJSON = template.JS(molJSON)
		}
	}

	return data
}

// buildStructuredFindings converts cleave findings into structured display data grouped by category.
// Findings are aggregated by directory path, keeping only the highest criticality/confidence per directory.
func buildStructuredFindings(files []cleaveFile) []FileFindingsDisplay {
	var result []FileFindingsDisplay

	// Category display names
	categoryNames := map[string]string{
		"objectives":      "Objectives",
		"micro-behaviors": "Micro-behaviors",
		"metadata":        "Metadata",
		"well-known":      "Well-known",
		"third_party":     "Third-party",
	}

	// Criticality ordering for comparison
	critOrder := map[string]int{
		"hostile":    3,
		"suspicious": 2,
		"notable":    1,
		"":           0,
	}

	for _, file := range files {
		if len(file.Findings) == 0 {
			continue
		}

		// Aggregate findings by directory path (everything except last component)
		// Key: "topLevel/dirPath", Value: best finding for that directory
		type aggregatedFinding struct {
			dirPath  string // Directory path without top-level (e.g., "execution/shell")
			topLevel string
			crit     string
			conf     float64
			desc     string
			evidence map[string]bool // Deduplicated evidence
		}
		aggregated := make(map[string]*aggregatedFinding)

		for _, f := range file.Findings {
			// Skip structural/internal findings
			if f.Kind == "structural" || strings.HasPrefix(f.ID, "metadata/internal/") {
				continue
			}

			// Only show notable or higher (skip baseline/component)
			if f.Crit != "hostile" && f.Crit != "suspicious" && f.Crit != "notable" {
				continue
			}

			// Split into parts: topLevel / rest
			parts := strings.Split(f.ID, "/")
			if len(parts) < 2 {
				continue
			}

			topLevel := parts[0]

			// Directory path is everything except the last component, excluding top-level
			// e.g., "objectives/execution/shell/bash" -> dirPath = "execution/shell"
			var dirPath string
			if len(parts) > 2 {
				dirPath = strings.Join(parts[1:len(parts)-1], "/")
			} else {
				// Only 2 parts like "objectives/execution" -> show as "execution"
				dirPath = parts[1]
			}

			key := topLevel + "/" + dirPath

			existing, ok := aggregated[key]
			if !ok {
				// New directory - create entry
				evidenceSet := make(map[string]bool)
				for _, e := range f.Evidence {
					evidenceSet[e.Value] = true
				}
				aggregated[key] = &aggregatedFinding{
					dirPath:  dirPath,
					topLevel: topLevel,
					crit:     f.Crit,
					conf:     f.Conf,
					desc:     f.Desc,
					evidence: evidenceSet,
				}
			} else {
				// Existing directory - keep higher criticality, then higher confidence
				existingCrit := critOrder[existing.crit]
				newCrit := critOrder[f.Crit]

				shouldReplace := newCrit > existingCrit ||
					(newCrit == existingCrit && f.Conf > existing.conf)

				if shouldReplace {
					existing.crit = f.Crit
					existing.conf = f.Conf
					existing.desc = f.Desc
				}

				// Merge evidence (always)
				for _, e := range f.Evidence {
					existing.evidence[e.Value] = true
				}
			}
		}

		// Group by top-level category
		categoryMap := make(map[string][]FindingDisplay)

		for _, agg := range aggregated {
			// Convert evidence map to sorted slice
			var evidence []string
			for e := range agg.evidence {
				evidence = append(evidence, e)
			}
			sort.Strings(evidence)

			fd := FindingDisplay{
				ID:       agg.dirPath, // Show directory path without top-level
				Crit:     agg.crit,
				Desc:     agg.desc,
				Evidence: evidence,
			}

			categoryMap[agg.topLevel] = append(categoryMap[agg.topLevel], fd)
		}

		// Sort findings within each category by criticality (desc), then alphabetically
		for cat := range categoryMap {
			findings := categoryMap[cat]
			sort.Slice(findings, func(i, j int) bool {
				ci, cj := critOrder[findings[i].Crit], critOrder[findings[j].Crit]
				if ci != cj {
					return ci > cj // Higher criticality first
				}
				return findings[i].ID < findings[j].ID // Alphabetical
			})
			categoryMap[cat] = findings
		}

		// Build categories in display order
		displayOrder := []string{"objectives", "micro-behaviors", "metadata", "well-known", "third_party"}
		var categories []CategoryGroup

		for _, cat := range displayOrder {
			if findings, ok := categoryMap[cat]; ok && len(findings) > 0 {
				name := categoryNames[cat]
				if name == "" {
					name = cat
				}
				categories = append(categories, CategoryGroup{
					Name:     name,
					Findings: findings,
				})
			}
		}

		if len(categories) > 0 {
			// Extract basename
			path := file.Path
			basename := path
			if strings.Contains(path, "!!") {
				parts := strings.Split(path, "!!")
				basename = parts[len(parts)-1]
			}
			if idx := strings.LastIndex(basename, "/"); idx >= 0 {
				basename = basename[idx+1:]
			}

			result = append(result, FileFindingsDisplay{
				Path:       file.Path,
				Basename:   basename,
				Risk:       file.Risk,
				SHA256:     file.SHA256,
				Formula:    formatFormula(file.FileType, file.Formula),
				Categories: categories,
			})
		}
	}

	return result
}

// buildStructuredStrings extracts strings data for table display.
func buildStructuredStrings(files []cleaveFile) []FileStringsDisplay {
	var result []FileStringsDisplay

	for _, file := range files {
		if len(file.Strings) == 0 {
			continue
		}

		basename := extractBasename(file.Path)
		var strs []StringDisplay
		for _, s := range file.Strings {
			strs = append(strs, StringDisplay{
				Value:   s.Value,
				Section: s.Section,
			})
		}

		result = append(result, FileStringsDisplay{
			Basename: basename,
			Risk:     file.Risk,
			SHA256:   file.SHA256,
			Formula:  formatFormula(file.FileType, file.Formula),
			Strings:  strs,
		})
	}

	return result
}

// buildStructuredSymbols extracts symbols data for table display.
func buildStructuredSymbols(files []cleaveFile) []FileSymbolsDisplay {
	var result []FileSymbolsDisplay

	for _, file := range files {
		if len(file.Imports) == 0 && len(file.Exports) == 0 {
			continue
		}

		basename := extractBasename(file.Path)
		var imports, exports []SymbolDisplay

		for _, s := range file.Imports {
			name := s.Symbol
			if name == "" {
				name = s.Name
			}
			imports = append(imports, SymbolDisplay{
				Name:    name,
				Library: s.Library,
			})
		}

		for _, s := range file.Exports {
			name := s.Symbol
			if name == "" {
				name = s.Name
			}
			exports = append(exports, SymbolDisplay{
				Name:    name,
				Library: s.Library,
			})
		}

		result = append(result, FileSymbolsDisplay{
			Basename: basename,
			Risk:     file.Risk,
			SHA256:   file.SHA256,
			Formula:  formatFormula(file.FileType, file.Formula),
			Imports:  imports,
			Exports:  exports,
		})
	}

	return result
}

// buildStructuredSections extracts sections data for table display.
func buildStructuredSections(files []cleaveFile) []FileSectionsDisplay {
	var result []FileSectionsDisplay

	for _, file := range files {
		if len(file.Sections) == 0 {
			continue
		}

		basename := extractBasename(file.Path)
		var sections []SectionDisplay

		for _, s := range file.Sections {
			sections = append(sections, SectionDisplay{
				Name:    s.Name,
				Size:    s.Size,
				Entropy: s.Entropy,
				Flags:   s.Flags,
			})
		}

		result = append(result, FileSectionsDisplay{
			Basename: basename,
			Risk:     file.Risk,
			SHA256:   file.SHA256,
			Formula:  formatFormula(file.FileType, file.Formula),
			Sections: sections,
		})
	}

	return result
}

// buildStructuredMetrics extracts metrics data for table display.
func buildStructuredMetrics(files []cleaveFile) []FileMetricsDisplay {
	var result []FileMetricsDisplay

	for _, file := range files {
		if file.Metrics == nil || file.Metrics.Binary == nil {
			continue
		}

		basename := extractBasename(file.Path)
		m := file.Metrics.Binary

		result = append(result, FileMetricsDisplay{
			Basename:       basename,
			Risk:           file.Risk,
			SHA256:         file.SHA256,
			Formula:        formatFormula(file.FileType, file.Formula),
			FileSize:       m.FileSize,
			CodeSize:       m.CodeSize,
			OverallEntropy: m.OverallEntropy,
			CodeEntropy:    m.CodeEntropy,
		})
	}

	return result
}

// extractBasename extracts the filename from a path, handling archive paths.
func extractBasename(path string) string {
	if strings.Contains(path, "!!") {
		parts := strings.Split(path, "!!")
		path = parts[len(parts)-1]
	}
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// formatFormula returns "FILETYPE:formula" format, e.g. "GO:H₂O"
func formatFormula(fileType, formula string) string {
	if formula == "" {
		return ""
	}
	return strings.ToUpper(fileType) + ":" + formula
}

// formatBytes formats bytes into human-readable format.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// formatTerminalOutput converts ANSI terminal output to HTML.
func formatTerminalOutput(s string) string {
	// Simple ANSI to HTML conversion
	replacer := strings.NewReplacer(
		"\x1b[0m", "</span>",
		"\x1b[1m", "<span style=\"font-weight:bold\">",
		"\x1b[31m", "<span class=\"hostile\">",
		"\x1b[91m", "<span class=\"hostile\">",
		"\x1b[33m", "<span class=\"suspicious\">",
		"\x1b[93m", "<span class=\"suspicious\">",
		"\x1b[34m", "<span class=\"notable\">",
		"\x1b[94m", "<span class=\"notable\">",
		"\x1b[90m", "<span class=\"dim\">",
		"\x1b[97m", "<span style=\"color:#fff\">",
		"\x1b[36m", "<span class=\"notable\">",
		"\x1b[96m", "<span class=\"notable\">",
	)

	result := replacer.Replace(html.EscapeString(s))

	// Unescape the span tags we just added
	result = strings.ReplaceAll(result, "&lt;span", "<span")
	result = strings.ReplaceAll(result, "&lt;/span&gt;", "</span>")
	result = strings.ReplaceAll(result, "&gt;", ">")
	result = strings.ReplaceAll(result, "&#34;", "\"")

	return result
}

// cleaveResult holds all output from cleave analysis
type cleaveResult struct {
	JSON     string
	Traits   string
	Strings  string
	Symbols  string
	Sections string
	Metrics  string
}

// initCleaveServer initializes the cleave server connection.
// If cleaveAddr is set, it connects to the existing server.
// Otherwise, it starts a new cleave server subprocess.
func initCleaveServer() error {
	// Initialize HTTP client for cleave server
	cleaveClient = &http.Client{
		Timeout: 150 * time.Second, // 120s analysis + buffer
	}

	if cleaveAddr != "" {
		// Connect to existing server
		logger.Info("connecting to existing cleave server", "addr", cleaveAddr)
		if err := waitForCleaveServer(30 * time.Second); err != nil {
			return fmt.Errorf("failed to connect to cleave server at %s: %w", cleaveAddr, err)
		}
		logger.Info("connected to cleave server", "addr", cleaveAddr)
		return nil
	}

	// Start our own cleave server
	resolvedCleavePath, err := exec.LookPath(cleavePath)
	if err != nil {
		return fmt.Errorf("cleave binary not found: %w (set CLEAVE_PATH to specify location)", err)
	}

	// Use a fixed port for the managed server
	cleaveAddr = "127.0.0.1:18080"

	// Increase max size to 200MB for larger files
	args := []string{"server", "--bind", cleaveAddr, "--max-size-mb", "200"}
	cleaveServerCmd = exec.Command(resolvedCleavePath, args...)

	// Set working directory to cleave directory (for cache lookup)
	// The cache is stored relative to the binary or working directory
	if traitsPath != "" {
		// If traits path is set, use its parent as the working directory
		// This helps find the cache when cleave is installed alongside its traits
		cleaveDir := filepath.Dir(traitsPath)
		cleaveServerCmd.Dir = cleaveDir
	}

	// Set environment for traits and third-party paths
	cleaveServerCmd.Env = os.Environ()
	if traitsPath != "" {
		cleaveServerCmd.Env = append(cleaveServerCmd.Env, "CLEAVE_TRAITS_DIR="+traitsPath)
	}
	if thirdPartyPath != "" {
		cleaveServerCmd.Env = append(cleaveServerCmd.Env, "CLEAVE_3P_DIR="+thirdPartyPath)
	}

	// Stream cleave server output directly to our stdout/stderr
	cleaveServerCmd.Stdout = os.Stdout
	cleaveServerCmd.Stderr = os.Stderr

	logger.Info("starting cleave server",
		"path", resolvedCleavePath,
		"args", args,
		"traits_dir", traitsPath,
		"third_party_dir", thirdPartyPath,
	)

	if err := cleaveServerCmd.Start(); err != nil {
		return fmt.Errorf("failed to start cleave server: %w", err)
	}

	// Wait for server to be ready (it takes ~27s to load YARA rules)
	logger.Info("waiting for cleave server to initialize (this may take up to 30 seconds)...")
	if err := waitForCleaveServer(60 * time.Second); err != nil {
		stopCleaveServer()
		return fmt.Errorf("cleave server failed to start: %w", err)
	}

	logger.Info("cleave server ready", "addr", cleaveAddr)
	return nil
}

// waitForCleaveServer polls the health endpoint until the server is ready.
func waitForCleaveServer(timeout time.Duration) error {
	healthURL := fmt.Sprintf("http://%s/health", cleaveAddr)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := cleaveClient.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for cleave server at %s", cleaveAddr)
}

// stopCleaveServer stops the managed cleave server if we started it.
func stopCleaveServer() {
	if cleaveServerCmd == nil || cleaveServerCmd.Process == nil {
		return
	}

	logger.Info("stopping cleave server")

	// Send SIGTERM for graceful shutdown
	if err := cleaveServerCmd.Process.Signal(syscall.SIGTERM); err != nil {
		logger.Warn("failed to send SIGTERM to cleave server", "error", err)
		cleaveServerCmd.Process.Kill()
		return
	}

	// Wait with timeout
	done := make(chan error, 1)
	go func() {
		_, err := cleaveServerCmd.Process.Wait()
		done <- err
	}()

	select {
	case <-done:
		logger.Info("cleave server stopped")
	case <-time.After(5 * time.Second):
		logger.Warn("cleave server did not stop gracefully, killing")
		cleaveServerCmd.Process.Kill()
	}
}

// cleaveAPIResponse represents the JSON response from cleave server's /analyze endpoint.
// This maps to cleave's AnalysisReport structure.
type cleaveAPIResponse struct {
	SchemaVersion string            `json:"schema_version"`
	Target        cleaveTargetInfo  `json:"target"`
	Files         []cleaveAPIFile   `json:"files"`
	Summary       *cleaveAPISummary `json:"summary,omitempty"`
	Metadata      cleaveAPIMetadata `json:"metadata"`

	// Top-level fields for single-file analysis (when files array is empty)
	Findings []finding          `json:"findings,omitempty"`
	Strings  []stringInfo       `json:"strings,omitempty"`
	Imports  []cleaveAPIImport  `json:"imports,omitempty"`
	Exports  []cleaveAPIExport  `json:"exports,omitempty"`
	Sections []cleaveAPISection `json:"sections,omitempty"`
	Metrics  *cleaveAPIMetrics  `json:"metrics,omitempty"`
}

type cleaveTargetInfo struct {
	Path     string `json:"path"`
	FileType string `json:"type"`
	Size     int64  `json:"size_bytes"`
	SHA256   string `json:"sha256"`
}

type cleaveAPIFile struct {
	ID       int                `json:"id"`
	Path     string             `json:"path"`
	ParentID *int               `json:"parent_id,omitempty"`
	Depth    int                `json:"depth"`
	FileType string             `json:"file_type"`
	SHA256   string             `json:"sha256"`
	Size     int64              `json:"size"`
	Risk     string             `json:"risk,omitempty"`
	Counts   *findingCounts     `json:"counts,omitempty"`
	Findings []finding          `json:"findings,omitempty"`
	Strings  []stringInfo       `json:"strings,omitempty"`
	Imports  []cleaveAPIImport  `json:"imports,omitempty"`
	Exports  []cleaveAPIExport  `json:"exports,omitempty"`
	Sections []cleaveAPISection `json:"sections,omitempty"`
	Metrics  *cleaveAPIMetrics  `json:"metrics,omitempty"`
	Formula  string             `json:"formula,omitempty"`
}

type cleaveAPIImport struct {
	Symbol  string `json:"symbol"`
	Library string `json:"library,omitempty"`
	Address string `json:"address,omitempty"`
}

type cleaveAPIExport struct {
	Symbol  string `json:"symbol"`
	Address string `json:"address,omitempty"`
}

type cleaveAPISection struct {
	Name       string  `json:"name"`
	Address    uint64  `json:"address,omitempty"`
	Size       int64   `json:"size"`
	Entropy    float64 `json:"entropy,omitempty"`
	Flags      string  `json:"flags,omitempty"`
	Permission string  `json:"permission,omitempty"`
}

type cleaveAPIMetrics struct {
	Binary *cleaveAPIBinaryMetrics `json:"binary,omitempty"`
}

type cleaveAPIBinaryMetrics struct {
	FileSize       int64   `json:"file_size,omitempty"`
	CodeSize       int64   `json:"code_size,omitempty"`
	OverallEntropy float64 `json:"overall_entropy,omitempty"`
	CodeEntropy    float64 `json:"code_entropy,omitempty"`
	SectionCount   int     `json:"section_count,omitempty"`
	ImportCount    int     `json:"import_count,omitempty"`
	ExportCount    int     `json:"export_count,omitempty"`
	StringCount    int     `json:"string_count,omitempty"`
}

type cleaveAPISummary struct {
	FilesAnalyzed      int   `json:"files_analyzed"`
	Hostile            int   `json:"hostile"`
	Suspicious         int   `json:"suspicious"`
	Notable            int   `json:"notable"`
	AnalysisDurationMs int64 `json:"analysis_duration_ms"`
}

type cleaveAPIMetadata struct {
	AnalysisDurationMs int64 `json:"analysis_duration_ms,omitempty"`
}

// runCleave sends a file to the cleave server for analysis and returns the result.
func runCleave(ctx context.Context, filePath string, reqLogger *slog.Logger) (*cleaveResult, error) {
	startTime := time.Now()

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	reqLogger.Info("sending file to cleave server",
		"cleave_addr", cleaveAddr,
		"file_path", filePath,
		"file_size", fileInfo.Size(),
	)

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file field
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	written, err := io.Copy(part, file)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file to form: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	reqLogger.Debug("multipart form created",
		"body_size", buf.Len(),
		"file_bytes_written", written,
		"content_type", writer.FormDataContentType(),
	)

	// Create request
	url := fmt.Sprintf("http://%s/analyze", cleaveAddr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.ContentLength = int64(buf.Len())

	reqLogger.Debug("sending HTTP request",
		"url", url,
		"content_length", req.ContentLength,
	)

	// Send request
	resp, err := cleaveClient.Do(req)
	if err != nil {
		reqLogger.Error("HTTP request failed",
			"error", err,
			"duration_ms", time.Since(startTime).Milliseconds(),
		)
		return nil, fmt.Errorf("failed to send request to cleave server: %w", err)
	}
	defer resp.Body.Close()

	reqLogger.Debug("received HTTP response",
		"status", resp.StatusCode,
		"duration_ms", time.Since(startTime).Milliseconds(),
	)

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		reqLogger.Error("cleave server returned error",
			"status", resp.StatusCode,
			"body", string(body),
		)
		return nil, fmt.Errorf("cleave server returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp cleaveAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse cleave response: %w", err)
	}

	// Convert API response to JSONL format expected by parseJSONL
	jsonl := convertToJSONL(&apiResp)

	reqLogger.Info("cleave analysis complete",
		"total_duration_ms", time.Since(startTime).Milliseconds(),
		"files_analyzed", len(apiResp.Files),
		"json_bytes", len(jsonl),
	)

	return &cleaveResult{
		JSON:     jsonl,
		Traits:   "", // Not used by template rendering
		Strings:  "",
		Symbols:  "",
		Sections: "",
		Metrics:  "",
	}, nil
}

// convertToJSONL converts a cleave API response to JSONL format for parseJSONL compatibility.
func convertToJSONL(resp *cleaveAPIResponse) string {
	var lines []string

	// If files array is empty, create a single file entry from top-level data
	if len(resp.Files) == 0 && resp.Target.Path != "" {
		entry := cleaveJSONLEntry{
			Type:     "file",
			ID:       0,
			Path:     resp.Target.Path,
			Depth:    0,
			FileType: resp.Target.FileType,
			SHA256:   resp.Target.SHA256,
			Size:     resp.Target.Size,
			Findings: resp.Findings,
			Strings:  resp.Strings,
		}

		// Determine risk level from findings
		for _, f := range resp.Findings {
			switch f.Crit {
			case "hostile":
				entry.Risk = "hostile"
			case "suspicious":
				if entry.Risk != "hostile" {
					entry.Risk = "suspicious"
				}
			case "notable":
				if entry.Risk == "" {
					entry.Risk = "notable"
				}
			}
		}

		// Count findings by criticality
		counts := &findingCounts{}
		for _, f := range resp.Findings {
			switch f.Crit {
			case "hostile":
				counts.Hostile++
			case "suspicious":
				counts.Suspicious++
			case "notable":
				counts.Notable++
			}
		}
		if counts.Hostile > 0 || counts.Suspicious > 0 || counts.Notable > 0 {
			entry.Counts = counts
		}

		// Convert imports
		for _, imp := range resp.Imports {
			entry.Imports = append(entry.Imports, symbolInfo{
				Symbol:  imp.Symbol,
				Library: imp.Library,
				Address: imp.Address,
			})
		}

		// Convert exports
		for _, exp := range resp.Exports {
			entry.Exports = append(entry.Exports, symbolInfo{
				Symbol:  exp.Symbol,
				Address: exp.Address,
			})
		}

		// Convert sections
		for _, sec := range resp.Sections {
			entry.Sections = append(entry.Sections, sectionInfo{
				Name:    sec.Name,
				Address: sec.Address,
				Size:    sec.Size,
				Entropy: sec.Entropy,
				Flags:   sec.Flags,
			})
		}

		// Convert metrics
		if resp.Metrics != nil && resp.Metrics.Binary != nil {
			entry.Metrics = &metricsInfo{
				Binary: &binaryMetrics{
					FileSize:       resp.Metrics.Binary.FileSize,
					CodeSize:       resp.Metrics.Binary.CodeSize,
					OverallEntropy: resp.Metrics.Binary.OverallEntropy,
					CodeEntropy:    resp.Metrics.Binary.CodeEntropy,
					SectionCount:   resp.Metrics.Binary.SectionCount,
					ImportCount:    resp.Metrics.Binary.ImportCount,
					ExportCount:    resp.Metrics.Binary.ExportCount,
					StringCount:    resp.Metrics.Binary.StringCount,
				},
			}
		}

		line, err := json.Marshal(entry)
		if err == nil {
			lines = append(lines, string(line))
		}
	}

	// Convert each file to a JSONL entry (for archives/multi-file analysis)
	for _, f := range resp.Files {
		entry := cleaveJSONLEntry{
			Type:     "file",
			ID:       f.ID,
			Path:     f.Path,
			Depth:    f.Depth,
			FileType: f.FileType,
			SHA256:   f.SHA256,
			Size:     f.Size,
			Risk:     f.Risk,
			Counts:   f.Counts,
			Findings: f.Findings,
			Strings:  f.Strings,
			Formula:  f.Formula,
		}

		// Convert imports
		for _, imp := range f.Imports {
			entry.Imports = append(entry.Imports, symbolInfo{
				Symbol:  imp.Symbol,
				Library: imp.Library,
				Address: imp.Address,
			})
		}

		// Convert exports
		for _, exp := range f.Exports {
			entry.Exports = append(entry.Exports, symbolInfo{
				Symbol:  exp.Symbol,
				Address: exp.Address,
			})
		}

		// Convert sections
		for _, sec := range f.Sections {
			entry.Sections = append(entry.Sections, sectionInfo{
				Name:    sec.Name,
				Address: sec.Address,
				Size:    sec.Size,
				Entropy: sec.Entropy,
				Flags:   sec.Flags,
			})
		}

		// Convert metrics
		if f.Metrics != nil && f.Metrics.Binary != nil {
			entry.Metrics = &metricsInfo{
				Binary: &binaryMetrics{
					FileSize:       f.Metrics.Binary.FileSize,
					CodeSize:       f.Metrics.Binary.CodeSize,
					OverallEntropy: f.Metrics.Binary.OverallEntropy,
					CodeEntropy:    f.Metrics.Binary.CodeEntropy,
					SectionCount:   f.Metrics.Binary.SectionCount,
					ImportCount:    f.Metrics.Binary.ImportCount,
					ExportCount:    f.Metrics.Binary.ExportCount,
					StringCount:    f.Metrics.Binary.StringCount,
				},
			}
		}

		line, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		lines = append(lines, string(line))
	}

	// Add summary entry
	if resp.Summary != nil {
		summary := cleaveJSONLEntry{
			Type:               "summary",
			FilesAnalyzed:      resp.Summary.FilesAnalyzed,
			Hostile:            resp.Summary.Hostile,
			Suspicious:         resp.Summary.Suspicious,
			Notable:            resp.Summary.Notable,
			AnalysisDurationMs: resp.Summary.AnalysisDurationMs,
		}
		line, err := json.Marshal(summary)
		if err == nil {
			lines = append(lines, string(line))
		}
	} else {
		// Generate summary from analysis data
		summary := cleaveJSONLEntry{
			Type:               "summary",
			FilesAnalyzed:      max(len(resp.Files), 1), // At least 1 file analyzed
			AnalysisDurationMs: resp.Metadata.AnalysisDurationMs,
		}

		// Count risk levels from files array
		for _, f := range resp.Files {
			switch f.Risk {
			case "hostile":
				summary.Hostile++
			case "suspicious":
				summary.Suspicious++
			case "notable":
				summary.Notable++
			}
		}

		// If no files array, count from top-level findings
		if len(resp.Files) == 0 {
			for _, f := range resp.Findings {
				switch f.Crit {
				case "hostile":
					summary.Hostile++
				case "suspicious":
					summary.Suspicious++
				case "notable":
					summary.Notable++
				}
			}
		}

		line, err := json.Marshal(summary)
		if err == nil {
			lines = append(lines, string(line))
		}
	}

	return strings.Join(lines, "\n")
}

// truncateString truncates a string to maxLen characters, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// uploadToGCS uploads data to GCS with exponential backoff retry.
func uploadToGCS(ctx context.Context, bucket, sha256Hex, filename string, r io.Reader, reqLogger *slog.Logger) error {
	if gcsClient == nil {
		return fmt.Errorf("GCS client not initialized")
	}

	objectPath := fmt.Sprintf("%s/%s", sha256Hex, filename)
	reqLogger.Debug("preparing GCS upload", "bucket", bucket, "object", objectPath)

	var attempt int
	startTime := time.Now()
	err := retry.Do(
		func() error {
			attempt++
			reqLogger.Debug("uploading to GCS",
				"bucket", bucket,
				"object", objectPath,
				"attempt", attempt,
			)

			wc := gcsClient.Bucket(bucket).Object(objectPath).NewWriter(ctx)
			wc.ContentType = "application/octet-stream"

			if _, err := io.Copy(wc, r); err != nil {
				wc.Close()
				// Seek back to start if it's a seeker for the next retry
				if rs, ok := r.(io.Seeker); ok {
					_, _ = rs.Seek(0, io.SeekStart)
				}
				return fmt.Errorf("write: %w", err)
			}

			if err := wc.Close(); err != nil {
				return fmt.Errorf("close: %w", err)
			}

			return nil
		},
		retry.Context(ctx),
		retry.Attempts(5),
		retry.MaxDelay(2*time.Minute),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.OnRetry(func(n uint, err error) {
			reqLogger.Warn("GCS upload retry",
				"attempt", n+1,
				"error", err,
				"bucket", bucket,
				"object", objectPath,
			)
		}),
	)

	if err == nil {
		reqLogger.Info("GCS upload complete", "duration_ms", time.Since(startTime).Milliseconds(), "bucket", bucket, "object", objectPath)
	}

	return err
}
