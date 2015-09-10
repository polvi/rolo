package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
	"github.com/polvi/procio/util"
	"github.com/polvi/rolo/client"
)

var (
	user      = flag.String("user", "", "")
	readonly  = flag.Bool("readonly", false, "")
	group     = flag.String("group", "", "")
	resource  = flag.String("resource", "", "")
	namespace = flag.String("namespace", "", "")

	rolodAddr          = flag.String("rolod-addr", "localhost:10003", "")
	idRefreshTokenFile = flag.String("identity-refresh-token-file", "", "Location of file containing refresh token")
	clientID           = flag.String("client-id", "XXX", "client id")
	clientSecret       = flag.String("client-secret", "secrete", "secret")
	discovery          = flag.String("discovery", "http://127.0.0.1:5556", "discovery url")
	redirectURL        = flag.String("redirect-url", "http://127.0.0.1:5555/callback", "Redirect URL for third leg of OIDC")
)

func getJWT(c *oidc.Client, listenAddr string) (*oauth2.Client, chan *oauth2.TokenResponse, error) {
	jwtChan := make(chan *oauth2.TokenResponse)
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, err
	}
	oac, err := c.OAuthClient()
	if err != nil {
		return nil, nil, err
	}
	f := func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			return
		}
		token, err := oac.RequestToken(oauth2.GrantTypeAuthCode, code)
		if err != nil {
			fmt.Fprintf(w, "error: %s", err)
			return
		}
		jwtChan <- &token
		fmt.Fprintf(w, "Success! You can now close this window and go back to the CLI")
		l.Close()
	}
	go http.Serve(l, http.HandlerFunc(f))
	return oac, jwtChan, err
}

func main() {
	flag.Parse()

	if *idRefreshTokenFile == "" {
		fmt.Println("Must set -refresh-token-file")
		return
	}
	oidcClient, err := util.GetOIDCClient(*clientID, *clientSecret, *discovery, *redirectURL)
	if err != nil {
		fmt.Println(err)
		return
	}
	var tok *oauth2.TokenResponse
	f, err := os.Open(*idRefreshTokenFile)
	defer f.Close()
	if err != nil {
		fmt.Println("error reading refresh token, fetching a new one and writing to", *idRefreshTokenFile)
		oac, jwtChan, err := getJWT(oidcClient, "localhost:5555")
		if err != nil {
			fmt.Println(err)
			return
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(oac.AuthCodeURL("", "", ""))
		tok = <-jwtChan
		f, err := os.Create(*idRefreshTokenFile)
		defer f.Close()
		if err != nil {
			fmt.Println(err)
			return
		}
		f.Write([]byte(tok.RefreshToken))
	}
	refToken, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	jwt, err := oidcClient.RefreshToken(string(refToken))
	if err != nil {
		fmt.Println(err)
		return
	}

	c, err := client.NewRoloClient(jwt, false, *rolodAddr, "", "")
	if err != nil {
		fmt.Println(err)
		return
	}
	allowed, err := c.Authorize(*user, *group, *resource, *namespace, *readonly)
	if err != nil {
		fmt.Println(err)
	}
	if !allowed {
		fmt.Println("not authorized")
		os.Exit(1)
	}
	fmt.Println("authorized")
}
