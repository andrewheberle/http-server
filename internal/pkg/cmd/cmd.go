package cmd

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/andrewheberle/http-server/pkg/httpserver"
	"github.com/bep/simplecobra"
	"github.com/spf13/afero"
)

type rootCommand struct {
	name string

	// flags
	listenAddress        string
	certificateFile      string
	keyFile              string
	httpRoot             string
	templatePath         string
	readTimeout          time.Duration
	writeTimeout         time.Duration
	includeRegexp        string
	debug                bool
	corsAllowedOrigins   []string
	corsAllowedMethods   []string
	corsAllowedHeaders   []string
	corsAllowCredentials bool
	corsMaxAge           time.Duration

	hs *httpserver.HttpServer

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
	cmd.Flags().StringVar(&c.includeRegexp, "include", "", "Regexp of files to include")
	cmd.Flags().BoolVar(&c.debug, "debug", false, "Enable debug logging")
	cmd.Flags().StringSliceVar(&c.corsAllowedOrigins, "cors-allowed-origins", []string{"*"}, "CORS Allowed Origins")
	cmd.Flags().StringSliceVar(&c.corsAllowedMethods, "cors-allowed-methods", []string{http.MethodGet, http.MethodPost}, "CORS Allowed Methods")
	cmd.Flags().StringSliceVar(&c.corsAllowedHeaders, "cors-allowed-headers", []string{}, "CORS Allowed Headers")
	cmd.Flags().BoolVar(&c.corsAllowCredentials, "cors-allowed-credentials", false, "CORS Allow Credentials")
	cmd.Flags().DurationVar(&c.corsMaxAge, "cors-max-age", 0, "CORS Max Age")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	// set up logger
	logLevel := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	if c.debug {
		logLevel.Set(slog.LevelDebug)
	}

	// set up options
	opts := []httpserver.HttpServerOption{
		httpserver.WithLogger(logger),
		httpserver.WithTimeout(c.readTimeout, c.writeTimeout),
	}

	// optionally enable TLS
	if c.certificateFile != "" && c.keyFile != "" {
		logger.Debug("setting up certificate", "cert", c.certificateFile, "key", c.keyFile)
		opts = append(opts, httpserver.WithCertificate(c.certificateFile, c.keyFile))
	}

	// optionally enable custom template
	if c.templatePath != "" {
		logger.Debug("setting up custom template", "template", c.templatePath)
		opts = append(opts, httpserver.WithTemplate(c.templatePath))
	}

	// set up ignores for web server
	if c.includeRegexp != "" {
		logger.Debug("setting up filtering of files", "include", c.includeRegexp)
		re, err := regexp.Compile(c.includeRegexp)
		if err != nil {
			return err
		}
		fs := afero.NewRegexpFs(afero.NewOsFs(), re)
		opts = append(opts, httpserver.WithFs(fs))
	}

	// add cors support
	if c.corsAllowCredentials {
		opts = append(opts, httpserver.WithCorsAllowCredentials(true))
	}
	if len(c.corsAllowedHeaders) > 0 {
		opts = append(opts, httpserver.WithCorsAllowedHeaders(c.corsAllowedHeaders...))
	}
	if len(c.corsAllowedMethods) > 0 {
		opts = append(opts, httpserver.WithCorsAllowedMethods(c.corsAllowedMethods...))
	}
	if len(c.corsAllowedOrigins) > 0 {
		opts = append(opts, httpserver.WithCorsAllowedOrigins(c.corsAllowedOrigins...))
	}
	if c.corsMaxAge > 0 {
		opts = append(opts, httpserver.WithCorsMaxAge(c.corsMaxAge))
	}

	// set up server
	logger.Debug("setting up server", "listen", c.listenAddress, "root", c.httpRoot)
	hs, err := httpserver.New(c.listenAddress, c.httpRoot, opts...)
	if err != nil {
		return err
	}
	c.hs = hs

	return nil
}

func (c *rootCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// start run group
	return c.hs.ListenAndServe()
}

func (c *rootCommand) Commands() []simplecobra.Commander {
	return c.commands
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
