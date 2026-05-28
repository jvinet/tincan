package version

import "runtime/debug"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func init() {
	if Version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	var revision, vcsTime string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision != "" {
		Commit = revision
		short := revision
		if len(short) > 7 {
			short = short[:7]
		}
		Version = short
		if modified {
			Version += "-dirty"
		}
	}
	if vcsTime != "" {
		Date = vcsTime
	}
}
