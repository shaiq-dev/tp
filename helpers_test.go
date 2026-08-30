package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// controlServer exercises the control plane over a real HTTP connection, with no
// unix socket and no forked daemon.
type controlServer struct{ url string }

func newControlServer(t *testing.T, d *daemon) controlServer {
	t.Helper()
	srv := httptest.NewServer(d.controlMux())
	t.Cleanup(srv.Close)
	return controlServer{url: srv.URL}
}

func (c controlServer) do(ctx context.Context, method, path, body string, out any) error {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url+path, r)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeControlResponse(resp, out)
}
