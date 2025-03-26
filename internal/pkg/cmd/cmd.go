package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/bep/simplecobra"
	"github.com/cloudflare/certinel/fswatcher"
	"github.com/oklog/run"
	sloghttp "github.com/samber/slog-http"
)

type rootCommand struct {
	name string

	// flags
	listenAddress   string
	certificateFile string
	keyFile         string
	httpRoot        string
	readTimeout     time.Duration
	writeTimeout    time.Duration
	templatePath    string

	logger          *slog.Logger
	browserTemplate *template.Template

	commands []simplecobra.Commander
}

func (c *rootCommand) Name() string {
	return c.name
}

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	cmd := cd.CobraCommand
	cmd.Short = "A simple HTTP server"

	// command line args
	cmd.Flags().StringVar(&c.listenAddress, "listen", "[::1]:8080", "Listen address")
	cmd.Flags().StringVar(&c.certificateFile, "cert", "", "SSL certificate for HTTPS")
	cmd.Flags().StringVar(&c.keyFile, "key", "", "SSL key for HTTPS")
	cmd.MarkFlagsRequiredTogether("cert", "key")
	cmd.Flags().StringVar(&c.httpRoot, "http-root", ".", "Path to HTTP content")
	cmd.Flags().DurationVar(&c.readTimeout, "read-timeout", time.Second*5, "Read timeout for HTTP requests")
	cmd.Flags().DurationVar(&c.writeTimeout, "write-timeout", time.Second*5, "Write timeout for HTTP responses")
	cmd.Flags().StringVar(&c.templatePath, "template", "", "Template to render file browser")

	// set up logger
	c.logger = slog.New(slog.NewTextHandler(os.Stdout, nil))

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	return nil
}

func (c *rootCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	var tlsConfig *tls.Config

	// set up run group
	g := run.Group{}

	// configure certificate use and reloads
	if c.certificateFile != "" && c.keyFile != "" {
		ctx, cancel := context.WithCancel(context.Background())
		certinel, err := fswatcher.New(c.certificateFile, c.keyFile)
		if err != nil {
			cancel()
			return fmt.Errorf("unable to read server certificate: %w", err)
		}

		tlsConfig = &tls.Config{
			GetCertificate: certinel.GetCertificate,
		}

		g.Add(func() error {
			c.logger.Info("starting up certificate watcher", "cert", c.certificateFile, "key", c.keyFile)
			return certinel.Start(ctx)
		}, func(err error) {
			if err != nil {
				c.logger.Error("error from certificate watcher", "error", err)
			} else {
				c.logger.Info("shutting down certificate watcher")
			}
			cancel()
		})
	}

	// set up http mux
	mux := http.NewServeMux()
	if c.templatePath == "" {
		mux.Handle("/", http.FileServer(http.Dir(c.httpRoot)))
	} else {
		// load template
		c.logger.Info("using custom template for file browser", "template", c.templatePath)
		if c.templatePath != "" {
			tmpl, err := template.
				New(filepath.Base(c.templatePath)).
				Funcs(template.FuncMap{
					"add":        add,
					"hasPrefix":  strings.HasPrefix,
					"hasSuffix":  strings.HasSuffix,
					"pathjoin":   path.Join,
					"split":      strings.Split,
					"trimPrefix": strings.TrimPrefix,
					"trimSuffix": strings.TrimSuffix,
				}).
				ParseFiles(c.templatePath)
			if err != nil {
				return fmt.Errorf("could not load template: %w", err)
			}

			c.browserTemplate = tmpl
		}
		mux.HandleFunc("/", c.fileHandler)
	}

	// add logging middleware
	handler := sloghttp.Recovery(mux)
	handler = sloghttp.New(c.logger)(handler)

	// set up http server
	srv := &http.Server{
		Addr:         c.listenAddress,
		Handler:      handler,
		ReadTimeout:  c.readTimeout,
		WriteTimeout: c.writeTimeout,
		TLSConfig:    tlsConfig,
	}

	g.Add(func() error {
		c.logger.Info("starting up http server", "listen", c.listenAddress)
		return srv.ListenAndServe()
	}, func(err error) {
		if err != nil {
			c.logger.Error("error from http server", "error", err)
		} else {
			c.logger.Info("shutting down http server")
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), c.writeTimeout)
			srv.Shutdown(ctx)
			cancel()
		}()
	})

	// start run group
	return g.Run()
}

func (c *rootCommand) Commands() []simplecobra.Commander {
	return c.commands
}

type templateData struct {
	Path     string
	FileList []fileInfo
}

type fileInfo struct {
	Name  string
	IsDir bool
}

func (c *rootCommand) fileHandler(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(c.httpRoot, r.URL.Path)
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}
	if info.IsDir() {
		files, err := os.ReadDir(path)
		if err != nil {
			http.Error(w, "Unable to read directory", http.StatusInternalServerError)
			return
		}
		fileNames := make([]fileInfo, 0)
		for _, file := range files {
			fileNames = append(fileNames, fileInfo{Name: file.Name(), IsDir: file.IsDir()})
		}

		// template data
		data := templateData{
			Path:     r.URL.Path,
			FileList: fileNames,
		}
		if err := c.browserTemplate.Execute(w, data); err != nil {
			c.logger.Error("error during template execution", "error", err)
		}
	} else {
		http.ServeFile(w, r, path)
	}
}

func Execute(args []string) error {
	// set up rootCmd
	rootCmd := &rootCommand{
		name: "http-server",
		commands: []simplecobra.Commander{
			&versionCommand{name: "version"},
		},
	}
	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	if _, err := x.Execute(context.Background(), args); err != nil {
		return err
	}

	return nil
}

func add(a, b int) int {
	return a + b
}
