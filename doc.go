// Package verisec is the official Go library for the VeriSec API: identity (KYC) checks on faces, documents,
// MRZ, contact details and sanctions, and Financial reads of cheques, payment cards, banks and BINs.
//
// Create a client with your key, then call an API:
//
//	client, err := verisec.New(os.Getenv("VERISEC_API_KEY")) // sk_test_… or ak_live_…
//	if err != nil {
//		log.Fatal(err)
//	}
//	result, err := client.Face.Verify(ctx, &verisec.FaceVerifyParams{
//		Image1: verisec.ImageFromPath("selfie.jpg"),
//		Image2: verisec.ImageFromPath("id-photo.jpg"),
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println(result.Match, result.Similarity, result.LastResponse.RequestID)
//
// Every API is a method named after its operationId (face.verify is Client.Face.Verify, phone.otp.send is
// Client.Phone.Otp.Send). It takes a context, its params (the operation's x-params-type, such as
// FaceVerifyParams) and request options, and returns the answer type: for KYC the envelope's data, for
// Financial the answer object, each with a LastResponse field (status, headers, request id, warnings,
// latency). The answers of the major APIs (Face Match, Document Read, Sanctions Screening, …) are open results:
// see OpenResult.
//
// KYC images are Image values (ImageFromPath, ImageFromBytes, ImageFromReader, ImageFromBase64), sent as base64;
// Financial uploads are *File values (FileFromPath, FileFromBytes, FileFromReader), sent as multipart/form-data.
//
// Live keys (ak_live_…) also take WithClientCredentials: the client exchanges them for a short-lived token and
// keeps it fresh. Calls are charged only when they succeed, so the client sends a call again only when nothing
// can have been charged (a 429, a 5xx, a connection that never opened), never after a timeout or a connection
// that dropped once the request was sent. Errors are *APIError (IsInsufficientCredits, IsRateLimited, …) and
// *ConnectionError values. ConstructEvent verifies and parses webhook deliveries (Standard Webhooks).
//
// The types and the resource methods are generated from the API's OpenAPI description (spec/openapi.json) by
// internal/gen: go generate ./... after the spec changes.
package verisec

//go:generate go run ./internal/gen -spec ../spec/openapi.json -out .
