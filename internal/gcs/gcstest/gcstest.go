// Package gcstest is an in-memory Cloud Storage for tests: the three JSON API
// calls package gcs makes, generation preconditions included.
package gcstest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Server holds objects by bucket and name.
type Server struct {
	*httptest.Server

	mu      sync.Mutex
	objects map[string]object // "bucket/name"
	gen     int64

	// Reads, Writes and Conflicts count requests, for tests that care.
	Reads, Writes, Conflicts atomic.Int64
}

type object struct {
	data []byte
	gen  int64
}

// New starts a server. Point a gcs.Client's Base at its URL.
func New() *Server {
	s := &Server{objects: map[string]object{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /storage/v1/b/{bucket}/o/{object...}", s.get)
	mux.HandleFunc("POST /upload/storage/v1/b/{bucket}/o", s.upload)
	s.Server = httptest.NewServer(mux)
	return s
}

// Object returns an object's content, or nil.
func (s *Server) Object(bucket, name string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.objects[bucket+"/"+name].data
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	s.Reads.Add(1)
	s.mu.Lock()
	o, ok := s.objects[r.PathValue("bucket")+"/"+r.PathValue("object")]
	s.mu.Unlock()
	if !ok {
		fail(w, http.StatusNotFound, "No such object")
		return
	}
	gen := strconv.FormatInt(o.gen, 10)
	if r.URL.Query().Get("alt") == "media" {
		w.Header().Set("X-Goog-Generation", gen)
		_, _ = w.Write(o.data)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"generation": gen})
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	s.Writes.Add(1)
	q := r.URL.Query()
	if q.Get("uploadType") != "media" || q.Get("name") == "" {
		fail(w, http.StatusBadRequest, "want uploadType=media and a name")
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	key := r.PathValue("bucket") + "/" + q.Get("name")

	s.mu.Lock()
	defer s.mu.Unlock()
	if m := q.Get("ifGenerationMatch"); m != "" {
		want, err := strconv.ParseInt(m, 10, 64)
		if err != nil || s.objects[key].gen != want {
			s.Conflicts.Add(1)
			fail(w, http.StatusPreconditionFailed, "At least one of the pre-conditions you specified did not hold.")
			return
		}
	}
	s.gen++
	s.objects[key] = object{data: data, gen: s.gen}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name":       q.Get("name"),
		"bucket":     r.PathValue("bucket"),
		"generation": strconv.FormatInt(s.gen, 10),
	})
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": strings.TrimSpace(msg)}})
}
