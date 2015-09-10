package main

import (
	"flag"
	"net"

	"github.com/polvi/procio/util"
	pb "github.com/polvi/rolo/proto"
	"github.com/polvi/rolo/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
)

var (
	policyFile = flag.String("policy-file", "", "kubernetes policy file")

	clientID     = flag.String("client-id", "XXX", "client id")
	clientSecret = flag.String("client-secret", "secrete", "secret")
	discovery    = flag.String("discovery", "http://127.0.0.1:5556", "discovery url")
	redirectURL  = flag.String("redirect-url", "http://127.0.0.1:5555/callback", "Redirect URL for third leg of OIDC")
	tls          = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	parentTls    = flag.Bool("parent-tls", false, "Connection uses TLS if true, else plain TCP")
	certFile     = flag.String("cert", "my.crt", "This servers TLS cert")
	keyFile      = flag.String("key", "my.key", "This servers TLS key")
	serverAddr   = flag.String("server-addr", "127.0.0.1:10001", "The server address in the format of host:port")
)

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", *serverAddr)
	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			grpclog.Fatalf("Failed to generate credentials %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(opts...)
	oidcClient, err := util.GetOIDCClient(*clientID, *clientSecret, *discovery, *redirectURL)
	if err != nil {
		grpclog.Fatalf("unable to get oidc client: %s", err)
	}
	s, err := server.NewRoloServer(oidcClient, *policyFile)
	if err != nil {
		grpclog.Fatalln("unable to create ca from parent:", err)
	}
	pb.RegisterRoloServer(grpcServer, s)
	grpclog.Println("serving at", *serverAddr)
	grpcServer.Serve(lis)
}
