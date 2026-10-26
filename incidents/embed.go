// Package incidents holds the built-in incident catalog.
package incidents

import "embed"

// FS holds every *.yaml file in this folder.
//
//go:embed *.yaml
var FS embed.FS
