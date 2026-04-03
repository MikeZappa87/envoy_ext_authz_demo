// policyengine/extproc.go
//
// ext_proc gRPC handler. Runs request-header and request-body phase
// policies through the same engine. Can deny via ImmediateResponse
// or mutate headers.
package main

import (
	"io"
	"log"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type extProcServer struct {
	ext_proc.UnimplementedExternalProcessorServer
	engine *Engine
}

func (s *extProcServer) Process(stream ext_proc.ExternalProcessor_ProcessServer) error {
	// Shared context across phases within the same stream (= same request).
	rctx := &RequestContext{
		Headers:       make(map[string]string),
		SetHeaders:    make(map[string]string),
		RemoveHeaders: nil,
	}

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
			hdrs := v.RequestHeaders.GetHeaders().GetHeaders()
			for _, h := range hdrs {
				rctx.Headers[h.GetKey()] = string(h.GetRawValue())
			}
			rctx.Method = rctx.Headers[":method"]
			rctx.Path = rctx.Headers[":path"]
			rctx.SpiffeID = rctx.Headers["x-spiffe-id"]
			rctx.Subject = rctx.Headers["x-cert-subject"]
			rctx.RequestID = rctx.Headers["x-request-id"]
			rctx.Phase = PhaseRequestHeaders

			// Strip internal identity headers so they don't leak to upstream.
			rctx.RemoveHeaders = append(rctx.RemoveHeaders, "x-spiffe-id", "x-cert-subject")

			log.Printf("extproc: request_headers phase path=%s spiffe=%s", rctx.Path, rctx.SpiffeID)

			result := s.engine.Run(rctx)
			if result.Action == ActionDeny {
				resp = extProcDeny(result)
			} else {
				resp = &ext_proc.ProcessingResponse{
					Response: &ext_proc.ProcessingResponse_RequestHeaders{
						RequestHeaders: &ext_proc.HeadersResponse{
							Response: buildCommonResponse(rctx),
						},
					},
				}
			}

		case *ext_proc.ProcessingRequest_RequestBody:
			rctx.Body = v.RequestBody.GetBody()
			rctx.Phase = PhaseRequestBody

			log.Printf("extproc: request_body phase (%d bytes)", len(rctx.Body))

			result := s.engine.Run(rctx)
			if result.Action == ActionDeny {
				resp = extProcDeny(result)
			} else {
				resp = &ext_proc.ProcessingResponse{
					Response: &ext_proc.ProcessingResponse_RequestBody{
						RequestBody: &ext_proc.BodyResponse{},
					},
				}
			}

		case *ext_proc.ProcessingRequest_ResponseHeaders:
			rctx.Phase = PhaseResponseHeaders

			log.Printf("extproc: response_headers phase")

			result := s.engine.Run(rctx)
			if result.Action == ActionDeny {
				resp = extProcDeny(result)
			} else {
				resp = &ext_proc.ProcessingResponse{
					Response: &ext_proc.ProcessingResponse_ResponseHeaders{
						ResponseHeaders: &ext_proc.HeadersResponse{
							Response: &ext_proc.CommonResponse{
								HeaderMutation: &ext_proc.HeaderMutation{
									SetHeaders: []*core.HeaderValueOption{
										{Header: &core.HeaderValue{
											Key: "x-policy-engine", RawValue: []byte("processed"),
										}},
									},
								},
							},
						},
					},
				}
			}

		default:
			continue
		}

		if err := stream.Send(resp); err != nil {
			return status.Errorf(codes.Internal, "send: %v", err)
		}
	}
}

func buildCommonResponse(rctx *RequestContext) *ext_proc.CommonResponse {
	if len(rctx.SetHeaders) == 0 && len(rctx.RemoveHeaders) == 0 {
		return nil
	}

	var setHdrs []*core.HeaderValueOption
	for k, v := range rctx.SetHeaders {
		setHdrs = append(setHdrs, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: k, RawValue: []byte(v)},
		})
	}

	return &ext_proc.CommonResponse{
		HeaderMutation: &ext_proc.HeaderMutation{
			SetHeaders:    setHdrs,
			RemoveHeaders: rctx.RemoveHeaders,
		},
	}
}

func extProcDeny(result *PolicyResult) *ext_proc.ProcessingResponse {
	return &ext_proc.ProcessingResponse{
		Response: &ext_proc.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &ext_proc.ImmediateResponse{
				Status: &typev3.HttpStatus{
					Code: typev3.StatusCode(result.StatusCode),
				},
				Body:    []byte(result.Message + "\n"),
				Details: "policy_engine_deny",
			},
		},
	}
}
