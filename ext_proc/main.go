// ext_proc/main.go
//
// External Processing (ext_proc) gRPC server for Envoy.
// Demonstrates request-body inspection: JSON payloads containing
// "action":"blocked" are rejected; everything else passes through
// with an injected x-body-inspected header.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type server struct {
	ext_proc.UnimplementedExternalProcessorServer
}

func (s *server) Process(stream ext_proc.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, "recv: %v", err)
		}

		var resp *ext_proc.ProcessingResponse

		switch v := req.Request.(type) {
		case *ext_proc.ProcessingRequest_RequestHeaders:
			log.Printf("ext_proc: request_headers phase")
			resp = &ext_proc.ProcessingResponse{
				Response: &ext_proc.ProcessingResponse_RequestHeaders{
					RequestHeaders: &ext_proc.HeadersResponse{},
				},
			}

		case *ext_proc.ProcessingRequest_RequestBody:
			body := v.RequestBody.GetBody()
			log.Printf("ext_proc: request_body phase (%d bytes)", len(body))

			resp = handleRequestBody(body)

		case *ext_proc.ProcessingRequest_ResponseHeaders:
			log.Printf("ext_proc: response_headers phase")
			resp = &ext_proc.ProcessingResponse{
				Response: &ext_proc.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &ext_proc.HeadersResponse{
						Response: &ext_proc.CommonResponse{
							HeaderMutation: &ext_proc.HeaderMutation{
								SetHeaders: []*core.HeaderValueOption{
									{
										Header: &core.HeaderValue{
											Key:   "x-ext-proc",
											Value: "body-inspected",
										},
									},
								},
							},
						},
					},
				},
			}

		case *ext_proc.ProcessingRequest_ResponseBody:
			log.Printf("ext_proc: response_body phase")
			resp = &ext_proc.ProcessingResponse{
				Response: &ext_proc.ProcessingResponse_ResponseBody{
					ResponseBody: &ext_proc.BodyResponse{},
				},
			}

		default:
			log.Printf("ext_proc: unknown phase, continuing")
			continue
		}

		if err := stream.Send(resp); err != nil {
			return status.Errorf(codes.Internal, "send: %v", err)
		}
	}
}

// handleRequestBody inspects a JSON body. If it contains "action":"blocked",
// the request is denied with a 403. Otherwise it passes through.
func handleRequestBody(body []byte) *ext_proc.ProcessingResponse {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		// Not valid JSON — let it through, upstream can deal with it.
		log.Printf("ext_proc: body is not JSON, allowing")
		return &ext_proc.ProcessingResponse{
			Response: &ext_proc.ProcessingResponse_RequestBody{
				RequestBody: &ext_proc.BodyResponse{},
			},
		}
	}

	if action, ok := payload["action"].(string); ok && action == "blocked" {
		log.Printf("ext_proc: DENIED — body contains action=blocked")
		return &ext_proc.ProcessingResponse{
			Response: &ext_proc.ProcessingResponse_ImmediateResponse{
				ImmediateResponse: &ext_proc.ImmediateResponse{
					Status: &typev3.HttpStatus{
						Code: typev3.StatusCode_Forbidden,
					},
					Body:    []byte("ext_proc: request body contains blocked action\n"),
					Details: "ext_proc_body_blocked",
				},
			},
		}
	}

	log.Printf("ext_proc: body OK, allowing")
	return &ext_proc.ProcessingResponse{
		Response: &ext_proc.ProcessingResponse_RequestBody{
			RequestBody: &ext_proc.BodyResponse{},
		},
	}
}

func main() {
	lis, err := net.Listen("tcp", ":9192")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	ext_proc.RegisterExternalProcessorServer(grpcServer, &server{})
	reflection.Register(grpcServer)

	fmt.Println("ext_proc listening on :9192")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
