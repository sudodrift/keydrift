package kd

import "strings"

func upper(s string) string       { return strings.ToUpper(s) }
func contains(s, sub string) bool { return strings.Contains(s, sub) }
func hasPrefix(s, p string) bool  { return strings.HasPrefix(s, p) }
func trimSpace(s string) string   { return strings.TrimSpace(s) }
