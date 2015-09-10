package client

import (
	"github.com/coreos/go-oidc/jose"
	grpcoidc "github.com/polvi/grpc-credentials/oidc"
	pb "github.com/polvi/rolo/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type RoloClient struct {
	grpcClient pb.RoloClient
}

func (c *RoloClient) Authorize(user, group, resource, namespace string, readonly bool) (bool, error) {
	authzResp, err := c.grpcClient.Authorize(context.Background(), &pb.Attributes{
		User:      user,
		Group:     group,
		ReadOnly:  readonly,
		Resource:  resource,
		Namespace: namespace,
	})
	if err != nil {
		return false, err
	}
	return authzResp.Authorized, nil
}

func NewRoloClient(idToken jose.JWT, tls bool, addr, serverHostOverride, trustedCaFile string) (*RoloClient, error) {
	var opts []grpc.DialOption
	creds := grpcoidc.NewOIDCAccess(&idToken)
	opts = append(opts, grpc.WithPerRPCCredentials(creds))
	if tls {
		var sn string
		if serverHostOverride != "" {
			sn = serverHostOverride
		}
		var creds credentials.TransportAuthenticator
		if trustedCaFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(trustedCaFile, sn)
			if err != nil {
				return nil, err
			}
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &RoloClient{
		grpcClient: pb.NewRoloClient(conn),
	}, nil
}
