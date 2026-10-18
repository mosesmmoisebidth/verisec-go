// Command quickstart makes three real calls: an MRZ parse, a BIN lookup and, given two photos, a face verify.
//
//	VERISEC_API_KEY=sk_test_… go run ./examples/quickstart selfie.jpg id-photo.jpg
//
// Against the local test server:
//
//	node ../test-server/server.mjs --port 4010
//	VERISEC_BASE_URL=http://127.0.0.1:4010 VERISEC_API_KEY=sk_test_demo go run ./examples/quickstart a.png b.png
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mosesmmoisebidth/verisec-go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// VERISEC_API_KEY (and VERISEC_BASE_URL, when set) configure the client.
	client, err := verisec.New(os.Getenv("VERISEC_API_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	// MRZ parse: the machine-readable lines of a passport, checked digit by digit.
	mrz, err := client.Mrz.Parse(ctx, &verisec.MrzParseParams{
		Lines: []string{
			"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
			"L898902C36UTO7408122F1204159ZE184226B<<<<<10",
		},
	})
	if err != nil {
		fail(err)
	}
	fmt.Println("MRZ:", mrz.Format, "valid", mrz.Valid, mrz.Parsed.Surname, mrz.Parsed.GivenName, mrz.Parsed.DocNumber, "request", mrz.LastResponse.RequestID)

	// BIN lookup: a card's network and issuer from its first digits.
	bin, err := client.Bin.Lookup(ctx, "424242")
	if err != nil {
		fail(err)
	}
	fmt.Println("BIN:", bin.Network, bin.Issuer, bin.Country)

	// Face verify: two photos of the same person?
	if len(os.Args) < 3 {
		fmt.Println("Pass two photos to compare them: go run ./examples/quickstart selfie.jpg id-photo.jpg")
		return
	}
	result, err := client.Face.Verify(ctx, &verisec.FaceVerifyParams{
		Image1: verisec.ImageFromPath(os.Args[1]),
		Image2: verisec.ImageFromPath(os.Args[2]),
	})
	if err != nil {
		fail(err)
	}
	fmt.Println("Same person:", result.Match, "similarity", result.Similarity, "request", result.LastResponse.RequestID)
}

func fail(err error) {
	var apiErr *verisec.APIError
	switch {
	case verisec.IsInsufficientCredits(err):
		log.Fatal("Not enough credits: top up in the console. Nothing was charged.")
	case errors.As(err, &apiErr):
		log.Fatalf("%s (status %d, code %s, request %s)", apiErr.Message, apiErr.Status, apiErr.Code, apiErr.RequestID)
	}
	log.Fatal(err)
}
