package verisec_test

// The README's examples, compiled with the tests (they have no Output, so they are not run).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mosesmmoisebidth/verisec-go"
)

func ExampleNew() {
	client, err := verisec.New(os.Getenv("VERISEC_API_KEY")) // sk_test_… or ak_live_…
	if err != nil {
		log.Fatal(err)
	}
	_ = client

	// a live key also takes its client id and secret
	live, err := verisec.New(os.Getenv("VERISEC_API_KEY"),
		verisec.WithClientCredentials(os.Getenv("VERISEC_CLIENT_ID"), os.Getenv("VERISEC_CLIENT_SECRET")),
		verisec.WithTimeout(5*time.Minute), verisec.WithMaxRetries(3))
	if err != nil {
		log.Fatal(err)
	}
	_ = live
}

func ExampleFaceService_Verify() {
	client, _ := verisec.New(os.Getenv("VERISEC_API_KEY"))
	idPhoto, _ := os.ReadFile("id-photo.jpg")
	result, err := client.Face.Verify(context.Background(), &verisec.FaceVerifyParams{
		Image1:    verisec.ImageFromPath("selfie.jpg"),
		Image2:    verisec.ImageFromBytes(idPhoto),
		Threshold: verisec.Float(0.8),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Match, result.Similarity)
	info := result.LastResponse
	fmt.Println(info.RequestID, info.Warnings, info.LatencyMs, info.Status, info.Header.Get("Content-Type"))
}

func ExampleFaceService_Search() {
	client, _ := verisec.New(os.Getenv("VERISEC_API_KEY"))
	ctx := context.Background()
	// entries hold their image; the index and ids are filled in when left out
	_, _ = client.Face.Match(ctx, &verisec.FaceMatchParams{
		Images: []verisec.FaceMatchParamsImage{
			{Data: verisec.ImageFromPath("selfie.jpg")},
			{Data: verisec.ImageFromPath("passport.jpg"), Type: verisec.Int(1)},
		},
	})
	search, err := client.Face.Search(ctx, &verisec.FaceSearchParams{
		Probe:   verisec.ImageFromPath("probe.jpg"),
		Gallery: []verisec.FaceSearchParamsGallery{{Image: verisec.ImageFromPath("a.jpg")}, {Image: verisec.ImageFromPath("b.jpg"), ID: verisec.String("user-42")}},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(search.Best, search.Matches)
}

func ExampleOpenResult() {
	client, _ := verisec.New(os.Getenv("VERISEC_API_KEY"))
	ctx := context.Background()
	screening, err := client.Screening.Sanctions(ctx, &verisec.ScreeningSanctionsParams{Name: "Jane Example"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(screening.Get("summary"), screening.LastResponse.RequestID)
	var hits struct {
		Results []struct {
			Name  string  `json:"name"`
			Score float64 `json:"score"`
			Match bool    `json:"match"`
		} `json:"results"`
	}
	if err := screening.Decode(&hits); err != nil {
		log.Fatal(err)
	}

	doc, err := client.Documents.Read(ctx, &verisec.DocumentReadParams{
		ImageFront: verisec.ImageFromPath("id-front.jpg"),
		ImageBack:  verisec.ImageFromPath("id-back.jpg"),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(doc.Raw["data"])
}

func ExampleChequesService_MicrLine() {
	client, _ := verisec.New(os.Getenv("VERISEC_API_KEY"))
	ctx := context.Background()
	chequeBytes, _ := os.ReadFile("cheque.jpg")
	cheque, err := client.Cheques.Read(ctx, &verisec.ChequeReadParams{Image: verisec.FileFromPath("cheque.jpg")})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cheque.Object)
	line, err := client.Cheques.MicrLine(ctx, &verisec.ChequeMicrLineParams{
		Image:  verisec.FileFromBytes(chequeBytes, "cheque.jpg"),
		Format: verisec.String("e13b"),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(line.Line.Text, line.LastResponse.RequestID)
	card, _ := client.Cards.Check(ctx, &verisec.CardCheckParams{Number: "4242 4242 4242 4242", Expiry: verisec.String("09/29")})
	bin, _ := client.Bin.Lookup(ctx, "424242")
	bank, _ := client.Banks.Lookup(ctx, &verisec.BankLookupParams{Name: verisec.String("Harbor Point Bank"), Country: verisec.String("US")})
	fmt.Println(card.SchemeValid, bin.Network, bank.Verified)
}

func ExampleAPIError() {
	client, _ := verisec.New(os.Getenv("VERISEC_API_KEY"))
	params := &verisec.FaceVerifyParams{Image1: verisec.ImageFromPath("selfie.jpg"), Image2: verisec.ImageFromPath("id-photo.jpg")}
	_, err := client.Face.Verify(context.Background(), params,
		verisec.WithRequestTimeout(time.Minute), verisec.WithRequestMaxRetries(0), verisec.WithHeader("X-Trace-Id", "abc"))
	if err != nil {
		var apiErr *verisec.APIError
		var connErr *verisec.ConnectionError
		switch {
		case verisec.IsInsufficientCredits(err):
			log.Print("Not enough credits (or the key's spend cap): top up in the console. Nothing was charged.")
		case errors.As(err, &apiErr) && verisec.IsRateLimited(err):
			log.Printf("Rate limited: wait %s.", apiErr.RetryAfter)
		case errors.As(err, &apiErr):
			log.Printf("%d %s (param %s, request %s): %s", apiErr.Status, apiErr.Code, apiErr.Param, apiErr.RequestID, apiErr.Message)
		case errors.As(err, &connErr):
			log.Printf("No answer (timeout: %v): %s", connErr.Timeout, connErr.Message)
		}
	}
}

func ExampleConstructEvent() {
	http.HandleFunc("/webhooks/verisec", func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		event, err := verisec.ConstructEvent(payload, r.Header, os.Getenv("VERISEC_WEBHOOK_SECRET"))
		if err != nil {
			http.Error(w, "bad signature", http.StatusBadRequest)
			return
		}
		if event.Type == "verification.completed" {
			fmt.Println(event.Data["decision"])
		}
		w.WriteHeader(http.StatusOK)
	})
}
