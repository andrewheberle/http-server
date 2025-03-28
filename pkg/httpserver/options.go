package httpserver

import (
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/spf13/afero"
)

type HttpServerOption func(*HttpServer)

func WithCertificate(cert, key string) HttpServerOption {
	return func(hs *HttpServer) {
		hs.certificateFile = filepath.Clean(cert)
		hs.keyFile = filepath.Clean(key)
	}
}

func WithTimeout(read, write time.Duration) HttpServerOption {
	return func(hs *HttpServer) {
		hs.readTimeout = read
		hs.writeTimeout = write
	}
}

func WithLogger(logger *slog.Logger) HttpServerOption {
	return func(hs *HttpServer) {
		hs.logger = logger
	}
}

func WithTemplate(tmpl string) HttpServerOption {
	return func(hs *HttpServer) {
		hs.templatePath = filepath.Clean(tmpl)
	}
}

func WithFs(fs afero.Fs) HttpServerOption {
	return func(hs *HttpServer) {
		hs.fs = fs
	}
}

func WithCorsAllowedOrigins(origins ...string) HttpServerOption {
	return func(hs *HttpServer) {
		hs.enableCors = true
		hs.corsAllowedOrigins = origins
	}
}

func WithCorsAllowedMethods(methods ...string) HttpServerOption {
	return func(hs *HttpServer) {
		hs.enableCors = true
		hs.corsAllowedMethods = methods
	}
}

func WithCorsAllowedHeaders(headers ...string) HttpServerOption {
	return func(hs *HttpServer) {
		hs.enableCors = true
		hs.corsAllowedHeaders = headers
	}
}

func WithCorsAllowCredentials(credentials bool) HttpServerOption {
	return func(hs *HttpServer) {
		hs.enableCors = true
		hs.corsAllowCredentials = credentials
	}
}

func WithCorsMaxAge(age time.Duration) HttpServerOption {
	return func(hs *HttpServer) {
		hs.enableCors = true
		hs.corsMaxAge = age
	}
}

func WithHandler(handler http.Handler) HttpServerOption {
	return func(hs *HttpServer) {
		hs.handler = handler
	}
}
