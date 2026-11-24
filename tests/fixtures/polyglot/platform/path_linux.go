package platform

func normalize(p string) string {
	out := ""
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' {
			out += "/"
		} else {
			out += string(p[i])
		}
	}
	return out
}

func Clean(p string) string { return normalize(p) }
