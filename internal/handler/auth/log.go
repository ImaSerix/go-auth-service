package auth

import (
	"log"
	"net/http"
)

func logError(r *http.Request, err error) {
	log.Printf(
		"method=%s path=%s err=%v",
		r.Method,
		r.URL.Path,
		err,
	)
}
