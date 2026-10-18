package verisec

// Optional fields of request params are pointers, so that "", false and 0 can be sent on purpose and nil means
// "not sent". These helpers make them in place:
//
//	client.Face.Verify(ctx, &verisec.FaceVerifyParams{
//		Image1:    verisec.ImageFromPath("selfie.jpg"),
//		Image2:    verisec.ImageFromPath("id-photo.jpg"),
//		Threshold: verisec.Float(0.8),
//		Tag:       verisec.String("signup-42"),
//	})
//
// Required scalars, slices, maps and images are plain values: a nil slice, map or image is not sent, and an
// empty but non-nil slice is sent as [].

// String returns a pointer to v, for an optional string field.
func String(v string) *string { return &v }

// Int returns a pointer to v, for an optional integer field.
func Int(v int64) *int64 { return &v }

// Float returns a pointer to v, for an optional number field.
func Float(v float64) *float64 { return &v }

// Bool returns a pointer to v, for an optional boolean field.
func Bool(v bool) *bool { return &v }
