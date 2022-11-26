package utils

import (
	"net/http"
	"strconv"
)

func PageAndPageSizeFromRequest(r *http.Request) (int, int) {
	strPage := r.URL.Query().Get("page")
	strPageSize := r.URL.Query().Get("page_size")
	page := 0
	pageSize := 50
	var err error
	if strPage != "" {
		page, err = strconv.Atoi(strPage)
		if err != nil {
			return page, pageSize
		}
	}
	if strPageSize != "" {
		pageSize, err = strconv.Atoi(strPageSize)
		if err != nil {
			return page, pageSize
		}
	}
	return page, pageSize
}
