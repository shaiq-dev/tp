package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// version is stamped by the release build with -ldflags "-X main.version=...".
// Builds that skip the Makefile, go install among them, leave it empty and fall
// back to the module version and VCS stamps in debug.BuildInfo.
var version string

type buildInfo struct {
	Version string
	Commit  string
	Date    string
	Dirty   bool
}

func readBuildInfo() buildInfo {
	b := buildInfo{Version: version}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if b.Version == "" {
			b.Version = "unknown"
		}
		return b
	}
	if b.Version == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		b.Version = info.Main.Version
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			b.Commit = s.Value
		case "vcs.time":
			b.Date = s.Value
		case "vcs.modified":
			b.Dirty = s.Value == "true"
		}
	}
	if b.Version == "" {
		b.Version = "devel"
	}
	return b
}

func (b buildInfo) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "tp %s", b.Version)
	if b.Commit != "" {
		commit := b.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		fmt.Fprintf(&sb, " (%s", commit)
		if b.Dirty {
			sb.WriteString("-dirty")
		}
		if b.Date != "" {
			fmt.Fprintf(&sb, ", %s", b.Date)
		}
		sb.WriteString(")")
	}
	fmt.Fprintf(&sb, "\n%s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return sb.String()
}
