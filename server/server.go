package server

import (
	"github.com/coreos/go-oidc/oidc"
	pb "github.com/polvi/rolo/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc/grpclog"
	"k8s.io/kubernetes/pkg/auth/authorizer"
	"k8s.io/kubernetes/pkg/auth/authorizer/abac"
	"k8s.io/kubernetes/pkg/auth/user"
)

type RoloServer struct {
	oidcClient *oidc.Client
	policyFile string
}

func NewRoloServer(oidcClient *oidc.Client, policyFile string) (*RoloServer, error) {
	return &RoloServer{
		oidcClient: oidcClient,
		policyFile: policyFile,
	}, nil
}

func (s *RoloServer) kubeAuthorize(a authorizer.Attributes) error {
	pl, err := abac.NewFromFile(s.policyFile)
	if err != nil {
		return err
	}
	return pl.Authorize(a)
}

func (s *RoloServer) Authorize(ctx context.Context, in *pb.Attributes) (*pb.AuthorizeResp, error) {

	attr := authorizer.AttributesRecord{
		User: &user.DefaultInfo{
			Name:   in.User,
			Groups: []string{in.Group},
		},
		ReadOnly:  in.ReadOnly,
		Namespace: in.Namespace,
		Resource:  in.Resource,
	}
	if err := s.kubeAuthorize(attr); err != nil {
		grpclog.Printf("Not Authorized %s", attr)
		return &pb.AuthorizeResp{
			Authorized: false,
		}, err
	}
	grpclog.Printf("Authorized %s", attr)
	return &pb.AuthorizeResp{
		Authorized: true,
	}, nil
}
