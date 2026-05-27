package log

import (
	"log/slog"
	"os"
)

func Setup() *slog.Logger {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	return logger
}
