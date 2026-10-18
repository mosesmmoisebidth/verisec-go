# VeriSec Go library

The official Go library for the VeriSec API: identity (KYC) checks on faces, documents, MRZ, contact details and
sanctions, and Financial reads of cheques, payment cards, banks and BINs. Typed requests and answers, images from
files, retries that never run a charged call twice, and webhook verification.

- Go 1.22 or later, standard library only.
- Version 1.0.0. Every API in `spec/openapi.yaml` (69 operations) is a method; the list with prices is in
  `spec/README.md`.

## Install

```sh
go get github.com/mosesmmoisebidth/verisec-go
```

```go
import "github.com/mosesmmoisebidth/verisec-go" // package verisec
```

## Configure

```go
client, err := verisec.New(os.Getenv("VERISEC_API_KEY")) // sk_test_… or ak_live_…
if err != nil {
    log.Fatal(err)
}
```

Create keys in the console under **API Keys**. A test key (`sk_test_…`) is sent as the bearer token. A live key
(`ak_live_…`) also needs the client id and secret issued with it; the client exchanges the three at
`POST /v2/oauth/token` for a short-lived token, keeps it until a minute before it expires (concurrent calls share
one exchange) and fetches a new one once when the API answers 401:

```go
client, err := verisec.New(os.Getenv("VERISEC_API_KEY"), // ak_live_…
    verisec.WithClientCredentials(os.Getenv("VERISEC_CLIENT_ID"), os.Getenv("VERISEC_CLIENT_SECRET")))
```

| Option | Default |
|---|---|
| `verisec.WithClientCredentials(id, secret)` | `VERISEC_CLIENT_ID`, `VERISEC_CLIENT_SECRET` |
| `verisec.WithBaseURL(u)` | `VERISEC_BASE_URL`, then `https://verisec.mmose.me` |
| `verisec.WithTimeout(d)` | 300 s per attempt (a deep cheque read can take about 250 s); 0 means no limit |
| `verisec.WithMaxRetries(n)` | 2 (0 turns retries off) |
| `verisec.WithHTTPClient(hc)` | an `*http.Client` of its own |

An empty key falls back to `VERISEC_API_KEY`. `New` returns `verisec.ErrNoAPIKey` without a key and
`verisec.ErrNoClientCredentials` for a live key without its client id and secret. A client is safe for concurrent
use: create one and share it.

## KYC: images from files

Every API is a method named after its operationId (`face.verify` is `client.Face.Verify`, `phone.otp.send` is
`client.Phone.Otp.Send`). Each takes a context, its params (`FaceVerifyParams`, …) and request options, and returns
the answer: for KYC the envelope's `data`.

```go
result, err := client.Face.Verify(ctx, &verisec.FaceVerifyParams{
    Image1:    verisec.ImageFromPath("selfie.jpg"),
    Image2:    verisec.ImageFromBytes(idPhoto),
    Threshold: verisec.Float(0.8),
})
if err != nil {
    return err
}
fmt.Println(result.Match, result.Similarity)
```

An image is a `verisec.Image`: `ImageFromPath(path)`, `ImageFromBytes(b)`, `ImageFromReader(r)` or
`ImageFromBase64(s)` (plain base64 or a `data:` URI). The client sends plain base64. An image that cannot be read
fails the call before anything is sent, with an error naming the field (`verisec: image2: reading the image: …`).

In a list of images, give each entry its image; the index and ids the API expects are filled in when you leave them
out (`index` 0, 1, …; `id` `face-1`, `face-2`, …). Your params are never changed.

```go
match, err := client.Face.Match(ctx, &verisec.FaceMatchParams{
    Images: []verisec.FaceMatchParamsImage{
        {Data: verisec.ImageFromPath("selfie.jpg")},
        {Data: verisec.ImageFromPath("passport.jpg"), Type: verisec.Int(1)}, // 1: printed (document)
    },
})

search, err := client.Face.Search(ctx, &verisec.FaceSearchParams{
    Probe:   verisec.ImageFromPath("probe.jpg"),
    Gallery: []verisec.FaceSearchParamsGallery{{Image: verisec.ImageFromPath("a.jpg")}, {Image: verisec.ImageFromPath("b.jpg"), ID: verisec.String("user-42")}},
})
```

Field names are Go names tagged with the API's exact spelling (it uses both `detectAll` and `image_front`), and
the doc comment of every type, field and method comes from the spec. Optional fields are pointers so that `""`,
`false` and `0` can be sent on purpose: `verisec.String`, `verisec.Int`, `verisec.Float` and `verisec.Bool` make them.
A nil slice is not sent; an empty one is sent as `[]`.

### Response info

Every result has a `LastResponse` field with the rest of the response:

```go
info := result.LastResponse
fmt.Println(info.RequestID, info.Warnings, info.LatencyMs, info.Status, info.Header.Get("Content-Type"))
```

Answer types keep the members they have no field for (a field the API added later, or a value whose JSON type
changed) in their `Extra` map, so nothing in an answer is lost and nothing breaks decoding.

### Open results

The major APIs (Face Analyze, Face Match, Age Estimation, Photo Quality, Liveness, Document Read, Proof of Address,
MRZ Read, IP Risk, Sanctions & PEP Screening, Contact Dossier) return the engine's full answer, which no fixed type
could list. Their result embeds a `verisec.OpenResult`: read it with `Raw` (the decoded JSON object), `Get(key)`, or
`Decode` into a struct of your own.

```go
screening, err := client.Screening.Sanctions(ctx, &verisec.ScreeningSanctionsParams{Name: "Jane Example"})
if err != nil {
    return err
}
fmt.Println(screening.Get("summary"), screening.LastResponse.RequestID)

var hits struct {
    Results []struct {
        Name  string  `json:"name"`
        Score float64 `json:"score"`
        Match bool    `json:"match"`
    } `json:"results"`
}
err = screening.Decode(&hits)

doc, err := client.Documents.Read(ctx, &verisec.DocumentReadParams{
    ImageFront: verisec.ImageFromPath("id-front.jpg"),
    ImageBack:  verisec.ImageFromPath("id-back.jpg"),
})
fields := doc.Raw["data"] // the engine's containers, as decoded JSON
```

## Financial: cheques, cards, banks, BIN

Cheque and card photos are uploaded as files (`multipart/form-data`, filed under "SDK" in the console's scan
logs), exactly as given:

```go
cheque, err := client.Cheques.Read(ctx, &verisec.ChequeReadParams{Image: verisec.FileFromPath("cheque.jpg")})

line, err := client.Cheques.MicrLine(ctx, &verisec.ChequeMicrLineParams{
    Image:  verisec.FileFromBytes(chequeBytes, "cheque.jpg"),
    Format: verisec.String("e13b"),
})
fmt.Println(line.Line.Text, line.LastResponse.RequestID)

card, err := client.Cards.Check(ctx, &verisec.CardCheckParams{Number: "4242 4242 4242 4242", Expiry: verisec.String("09/29")})
bin, err := client.Bin.Lookup(ctx, "424242")
bank, err := client.Banks.Lookup(ctx, &verisec.BankLookupParams{Name: verisec.String("Harbor Point Bank"), Country: verisec.String("US")})
```

A file is `verisec.FileFromPath(path)`, `FileFromBytes(b, filename)` or `FileFromReader(r, filename)`. Financial
answers are returned as the API sends them (`cheque.Object` is `"cheque_read"`), with the same `LastResponse`.

## Credits

Each call costs its API's price in credits, charged only when it succeeds. Refused calls (no credits, no
permission, rate limited) and calls that could not run are free.

## Errors

```go
result, err := client.Face.Verify(ctx, params)
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
    return err // also: your context ended, or an image could not be read
}
```

`*verisec.APIError` has `Status`, `Code`, `Message`, `Param`, `RequestID`, `RetryAfter` and `Header`. Its family:
`IsInvalidRequest` (400, 413, 415, 422), `IsAuthentication` (401), `IsInsufficientCredits` (402), `IsPermission`
(403), `IsNotFound` (404), `IsRateLimited` (429), `IsServerError` (5xx). A KYC answer with `ok: false` is an
`*APIError` too, never a result. `*verisec.ConnectionError` means no answer (`Timeout` when an attempt ran out of
time).

## Retries

The client sends a call again (up to `WithMaxRetries`, with backoff `min(0.5 × 2ⁿ, 8)` s ±25%, or what `Retry-After`
says, at most a minute) only when nothing can have been charged: a 429, a 5xx, or a connection that never opened
(refused, DNS failure, unreachable, connect timeout). It never sends a call again after a timeout, or after a
connection that dropped once the request went out, because the check may already have run and been charged; you get
a `*verisec.ConnectionError` saying so. Other 4xx answers are never retried.

## Per-request options

```go
client.Cheques.Read(ctx, params,
    verisec.WithRequestTimeout(5*time.Minute),
    verisec.WithRequestMaxRetries(0),
    verisec.WithHeader("X-Trace-Id", traceID),
    verisec.WithExtraField("new_option", true), // a parameter this version has no field for yet
)
```

## Webhooks

Deliveries are signed as Standard Webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature`; the `svix-*`
names work too). Pass the raw body, the headers and your endpoint's signing secret (`whsec_…`):

```go
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
```

`verisec.VerifySignature(payload, headers, secret)` only checks; both take an optional tolerance (default
5 minutes) and return a `*verisec.SignatureVerificationError` for a bad or stale signature.
`verisec.GenerateTestHeaders(payload, secret)` signs a body for your own tests.

## Example

`examples/quickstart` makes three calls: an MRZ parse, a BIN lookup and a face verify with two photos.

```sh
VERISEC_API_KEY=sk_test_… go run ./examples/quickstart selfie.jpg id-photo.jpg
```

## Development

```sh
go run ./internal/gen   # after the spec changes: rewrites types.go and resources.go (or go generate ./...)
go test ./...           # unit tests, plus integration tests against the shared test server
```

`types.go` and `resources.go` are generated from `../spec/openapi.json` by `internal/gen`; the rest is written by
hand. The integration tests start `node ../test-server/server.mjs --port 4022` (Node.js needed), call every
operation against it and stop it at the end; `go test -short ./...` runs the unit tests only.
