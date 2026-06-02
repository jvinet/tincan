package drop

import (
	"encoding/json"
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

func TestPublicReadPolicy(t *testing.T) {
	policy, err := publicReadPolicy("tincan", "directory.bin")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version   string
		Statement []struct {
			Effect    string
			Principal struct{ AWS []string }
			Action    []string
			Resource  []string
		}
	}
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		t.Fatalf("policy is not valid JSON: %v\n%s", err, policy)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("want 1 statement, got %d: %s", len(doc.Statement), policy)
	}
	st := doc.Statement[0]
	if st.Effect != "Allow" {
		t.Errorf("effect = %q, want Allow", st.Effect)
	}
	if len(st.Action) != 1 || st.Action[0] != "s3:GetObject" {
		t.Errorf("action = %v, want [s3:GetObject]", st.Action)
	}
	// Scoped to the single published object, not the whole bucket.
	if len(st.Resource) != 1 || st.Resource[0] != "arn:aws:s3:::tincan/directory.bin" {
		t.Errorf("resource = %v, want [arn:aws:s3:::tincan/directory.bin]", st.Resource)
	}
	if len(st.Principal.AWS) != 1 || st.Principal.AWS[0] != "*" {
		t.Errorf("principal = %v, want [*]", st.Principal.AWS)
	}
}
