// Copyright 2021 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build go1.16

package main

import (
	"bytes"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/netsec-ethz/scion-apps/pkg/shttp"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	mungedScionAddr = regexp.MustCompile(`^(\d+)-([_\dA-Fa-f]+)-(.*)$`)
)

const (
	mungedScionAddrIAIndex   = 1
	mungedScionAddrASIndex   = 2
	mungedScionAddrHostIndex = 3
)

//go:embed skip.pac
var skipPAC string
var skipPACtemplate = template.Must(template.New("skip.pac").Parse(skipPAC))

type skipPACTemplateParams struct {
	ProxyAddress string
}

func main() {
	var bindAddress *net.TCPAddr
	kingpin.Flag("bind", "Address to bind on").Default("localhost:8888").TCPVar(&bindAddress)
	kingpin.Parse()

	/*
		transport := shttp.NewRoundTripper(&tls.Config{InsecureSkipVerify: true}, nil)
		defer transport.Close()
		proxy := &proxyHandler{
			transport: transport,
		}
		r := mux.NewRouter()
		r.HandleFunc("/skip.pac", handleWPAD).Host("localhost")
		if bindAddress.IP != nil {
			r.HandleFunc("/skip.pac", handleWPAD).Host(bindAddress.IP.String())
		}
		r.HandleFunc("/", handleTunneling).Methods("CONNECT")
		r.Handle("/", proxy) // everything else
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.Println(r.RequestURI, r.Method)
				next.ServeHTTP(w, r)
			})
		})
		r.Use(func(next http.Handler) http.Handler {
			return handlers.LoggingHandler(os.Stdout, next)
		})
	*/
	server := &http.Server{
		Addr:    bindAddress.String(),
		Handler: http.HandlerFunc(handleTunneling),
	}
	log.Fatal(server.ListenAndServe())
}

func handleWPAD(w http.ResponseWriter, req *http.Request) {
	buf := &bytes.Buffer{}
	err := skipPACtemplate.Execute(buf, skipPACTemplateParams{ProxyAddress: req.Host})
	if err != nil {
		http.Error(w, "error executing template", 500)
		return
	}
	w.Header().Set("content-type", "application/x-ns-proxy-autoconfig")
	_, _ = w.Write(buf.Bytes())
}

type proxyHandler struct {
	transport http.RoundTripper
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	fmt.Println("proxy", req.Host, req.Method)
	host := demunge(req.Host)
	req.Host = host
	req.URL.Scheme = "https"
	req.URL.Host = host

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func handleTunneling(w http.ResponseWriter, req *http.Request) {
	fmt.Println(req.Host, req.Method)
	/*
		session, err := appquic.DialEarly(
			r.Host,
			&tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3-29", "h3-32"},
			},
			nil)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		fmt.Println("dialed", session.LocalAddr(), session.RemoteAddr())
		dest_conn, err := session.OpenStream()
	*/
	transport := shttp.NewRoundTripper(&tls.Config{InsecureSkipVerify: true}, nil)
	defer transport.Close()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		panic("Hijacking not supported")
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer("d->c", dest_conn, client_conn)
	go transfer("c->d", client_conn, dest_conn)
}

func transfer(dir string, dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	fmt.Println("copying")
	buf := make([]byte, 1024)
	var err error
	var written int64
	for {
		nr, er := src.Read(buf)
		fmt.Println(dir, "read", nr, er)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write")
				}
			}
			written += int64(nw)
			fmt.Println(dir, err, written)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	fmt.Println(dir, err, written)
}

// demunge reverts the host name to a proper SCION address, from the format
// that had been entered in the browser.
func demunge(host string) string {
	parts := mungedScionAddr.FindStringSubmatch(host)
	if parts != nil {
		// directly apply mangling as in appnet.MangleSCIONAddr
		return fmt.Sprintf("[%s-%s,%s]",
			parts[mungedScionAddrIAIndex],
			strings.ReplaceAll(parts[mungedScionAddrASIndex], "_", ":"),
			parts[mungedScionAddrHostIndex],
		)
	}
	return host
}
