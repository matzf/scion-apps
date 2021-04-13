package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/gorilla/handlers"
	"github.com/lucas-clemente/quic-go"
	"github.com/netsec-ethz/scion-apps/pkg/appnet/appquic"
	"github.com/netsec-ethz/scion-apps/pkg/shttp"
)

func main() {

	hosts := []string{
		"scionlab.org",
		"www.scionlab.org",
		"docs.scionlab.org",
		"www.scion-architecture.net",
		"netsec.ethz.ch",
		"element.inf.ethz.ch",
	}
	mux := http.NewServeMux()
	for _, host := range hosts {
		u, err := url.Parse(fmt.Sprintf("https://%s/", host))
		if err != nil {
			panic(err)
		}
		mux.Handle(host+"/", httputil.NewSingleHostReverseProxy(u))
	}
	// Fallback: return 502
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "502 bad gateway", http.StatusBadGateway)
	})

	loggedMux := handlers.LoggingHandler(
		os.Stdout,
		mux,
	)

	go func() {
		log.Fatalf("%s", shttp.ListenAndServe(":80", loggedMux))
	}()

	hostSet := make(map[string]struct{})
	for _, h := range hosts {
		hostSet[h] = struct{}{}
	}
	log.Fatalf("%s", forwardTLS(hostSet))
}

func forwardTLS(hosts map[string]struct{}) error {
	listener, err := listen(":443")
	if err != nil {
		return err
	}
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go handleSession(hosts, sess)
	}

}

func handleSession(hosts map[string]struct{}, sess quic.Session) {
	sni := sess.ConnectionState().ServerName
	if _, ok := hosts[sni]; !ok {
		sess.CloseWithError(500, "bad gateway") // hihi
		return
	}
	dest_conn, err := net.Dial("tcp", sni+":443")
	if err != nil {
		sess.CloseWithError(500, "bad gateway")
		return
	}
	client_conn, err := sess.AcceptStream(context.Background())
	go transfer("d->c", dest_conn, client_conn)
	transfer("c->d", client_conn, dest_conn)
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

func listen(addr string) (quic.Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		NextProtos:   []string{shttp.NextProtoRaw},
		Certificates: appquic.GetDummyTLSCerts(),
	}
	return appquic.Listen(laddr, tlsCfg, nil)
}
