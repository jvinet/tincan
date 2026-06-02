package drop

import (
	"errors"
	"testing"

	"github.com/minio/minio-go/v7"
)

func TestMapS3Err(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"nil", nil, nil},
		// AccessDenied is the common "object isn't public" case; minio-go also
		// synthesizes it (empty Code) for bodyless HEAD/Stat 403 responses.
		{"access denied", minio.ErrorResponse{StatusCode: 403, Code: "AccessDenied"}, ErrForbidden},
		{"bodyless head 403", minio.ErrorResponse{StatusCode: 403, Code: ""}, ErrForbidden},
		// Genuine credential problems stay ErrAuth.
		{"bad signature", minio.ErrorResponse{StatusCode: 403, Code: "SignatureDoesNotMatch"}, ErrAuth},
		{"bad access key", minio.ErrorResponse{StatusCode: 403, Code: "InvalidAccessKeyId"}, ErrAuth},
		{"unauthorized", minio.ErrorResponse{StatusCode: 401, Code: "Unauthorized"}, ErrAuth},
		{"missing object", minio.ErrorResponse{StatusCode: 404, Code: "NoSuchKey"}, ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapS3Err(tc.err)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
