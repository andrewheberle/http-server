package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/cloudflare/certinel/fswatcher"
	"github.com/oklog/run"
	"github.com/rs/cors"
	sloghttp "github.com/samber/slog-http"
	"github.com/spf13/afero"
)

type HttpServer struct {
	httpRoot             string
	certificateFile      string
	keyFile              string
	readTimeout          time.Duration
	writeTimeout         time.Duration
	templatePath         string
	enableCors           bool
	corsAllowedOrigins   []string
	corsAllowedMethods   []string
	corsAllowedHeaders   []string
	corsAllowCredentials bool
	corsMaxAge           time.Duration

	g               run.Group
	logger          *slog.Logger
	browserTemplate *template.Template
	fs              afero.Fs
}

func New(listen, root string, opts ...HttpServerOption) (*HttpServer, error) {
	hs := new(HttpServer)

	// set defaults
	hs.readTimeout = time.Second * 5
	hs.writeTimeout = time.Second * 5
	hs.logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	hs.fs = afero.NewOsFs()

	// apply options
	for _, o := range opts {
		o(hs)
	}

	// passed options we need later
	hs.httpRoot = root

	var tlsConfig *tls.Config

	// set up run group
	hs.g = run.Group{}

	// configure certificate use and reloads
	if hs.certificateFile != "" && hs.keyFile != "" {
		ctx, cancel := context.WithCancel(context.Background())
		certinel, err := fswatcher.New(hs.certificateFile, hs.keyFile)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("unable to read server certificate: %w", err)
		}

		tlsConfig = &tls.Config{
			GetCertificate: certinel.GetCertificate,
		}

		hs.g.Add(func() error {
			hs.logger.Info("starting up certificate watcher", "cert", hs.certificateFile, "key", hs.keyFile)
			return certinel.Start(ctx)
		}, func(err error) {
			if err != nil {
				hs.logger.Error("error from certificate watcher", "error", err)
			} else {
				hs.logger.Info("shutting down certificate watcher")
			}
			cancel()
		})
	}

	// set up http mux
	mux := http.NewServeMux()
	if hs.templatePath == "" {
		httpFs := afero.NewHttpFs(hs.fs)
		mux.Handle("/", http.FileServer(httpFs.Dir(hs.httpRoot)))
	} else {
		// load template
		hs.logger.Info("using custom template for file browser", "template", hs.templatePath)
		if hs.templatePath != "" {
			tmpl, err := template.
				New(filepath.Base(hs.templatePath)).
				Funcs(template.FuncMap{
					"add":        add,
					"hasPrefix":  strings.HasPrefix,
					"hasSuffix":  strings.HasSuffix,
					"pathjoin":   path.Join,
					"split":      strings.Split,
					"trimPrefix": strings.TrimPrefix,
					"trimSuffix": strings.TrimSuffix,
				}).
				ParseFiles(hs.templatePath)
			if err != nil {
				return nil, fmt.Errorf("could not load template: %w", err)
			}
			hs.logger.Debug("template loaded", "templates", tmpl.DefinedTemplates())

			hs.browserTemplate = tmpl
		}
		mux.HandleFunc("/", hs.fileHandler)
	}

	// add final chain of handlers/middleware
	var handler http.Handler
	if hs.enableCors {
		hs.logger.Debug(
			"enabling CORS support",
			"origins", hs.corsAllowedOrigins,
			"methods", hs.corsAllowedMethods,
			"headers", hs.corsAllowedHeaders,
			"credentials", hs.corsAllowCredentials,
			"max-age", hs.corsMaxAge,
		)
		c := cors.New(cors.Options{
			AllowedOrigins:   hs.corsAllowedOrigins,
			AllowedMethods:   hs.corsAllowedMethods,
			AllowedHeaders:   hs.corsAllowedHeaders,
			AllowCredentials: hs.corsAllowCredentials,
		})
		handler = c.Handler(mux)
	}
	handler = sloghttp.Recovery(handler)
	handler = sloghttp.New(hs.logger)(handler)

	// set up http server
	srv := &http.Server{
		Addr:         listen,
		Handler:      handler,
		ReadTimeout:  hs.readTimeout,
		WriteTimeout: hs.writeTimeout,
		TLSConfig:    tlsConfig,
	}

	hs.g.Add(func() error {
		hs.logger.Info("starting up http server", "listen", listen)
		return srv.ListenAndServe()
	}, func(err error) {
		if err != nil {
			hs.logger.Error("error from http server", "error", err)
		} else {
			hs.logger.Info("shutting down http server")
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), hs.writeTimeout)
			srv.Shutdown(ctx)
			cancel()
		}()
	})

	return hs, nil
}

func (hs *HttpServer) ListenAndServe() error {
	return hs.g.Run()
}

type TemplateData struct {
	Path     string
	FileList []FileInfo
}

type FileInfo struct {
	Name  string
	IsDir bool
}

func (hs *HttpServer) fileHandler(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(hs.httpRoot, r.URL.Path)
	info, err := hs.fs.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if info.IsDir() {
		files, err := afero.ReadDir(hs.fs, path)
		if err != nil {
			http.Error(w, "Unable to read directory", http.StatusInternalServerError)
			return
		}

		fileNames := make([]FileInfo, 0)
		for _, file := range files {
			fileNames = append(fileNames, FileInfo{Name: file.Name(), IsDir: file.IsDir()})
		}

		// template data
		data := TemplateData{
			Path:     r.URL.Path,
			FileList: fileNames,
		}
		hs.logger.Debug("template data", "data", data)
		if err := hs.browserTemplate.Execute(w, data); err != nil {
			hs.logger.Error("error during template execution", "error", err)
		}
	} else {
		http.ServeFile(w, r, path)
	}
}

func add(a, b int) int {
	return a + b
}
