package dnsprovider

func quoteTXT(s string) string {
	return `"` + s + `"`
}

// unquoteTXT strips one DNS presentation-format quote pair. Tincan writes
// single-string TXT values under 255 bytes, so there is no split-string parsing
// to do here.
func unquoteTXT(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
