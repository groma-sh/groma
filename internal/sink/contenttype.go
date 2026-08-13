package sink

import "strings"

// contentType keeps evidence browsable straight out of a bucket: a signed HTML
// report an auditor can open in a browser is worth more than one that downloads
// as an octet-stream.
func contentType(fileName string) string {
	switch {
	case strings.HasSuffix(fileName, ".json"):
		return "application/json"
	case strings.HasSuffix(fileName, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(fileName, ".pem"):
		return "application/x-pem-file"
	default:
		return "text/plain; charset=utf-8"
	}
}

func contentTypePtr(fileName string) *string {
	t := contentType(fileName)
	return &t
}
