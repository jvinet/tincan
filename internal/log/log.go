package log

import (
	"log/slog"
	"os"
)

func Setup(json bool) *slog.Logger {
	var handler slog.Handler
	if json {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		handler = slog.NewTextHandler(os.Stderr, nil)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}
