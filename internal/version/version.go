package version

import "runtime/debug"

// Version is stamped at link time:
//
//	-ldflags "-X github.com/groma-sh/groma/internal/version.Version=v0.1.0"
var Version = ""

// Get falls back to the build info Go embeds when Version wasn't stamped.
func Get() string {
	if Version != "" {
		return Version
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	var revision string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if revision == "" {
		// Built with -buildvcs=false, or outside a repository.
		return "unknown"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if dirty {
		return "devel+" + revision + ".dirty"
	}
	return "devel+" + revision
}
