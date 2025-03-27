package httpserver

import (
	"log/slog"
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
