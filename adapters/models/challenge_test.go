package dosProtectorAdapterModels

import (
	"crypto/sha256"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pow "github.com/thewizardplusplus/go-pow"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestNewChallengeFromEntity(test *testing.T) {
	type args struct {
		entity pow.Challenge
	}

	for _, data := range []struct {
		name    string
		args    args
		want    Challenge
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			args: args{
				entity: func() pow.Challenge {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					createdAt, err := powValueTypes.NewCreatedAt(
						time.Date(2000, time.January, 2, 3, 4, 5, 6, time.UTC),
					)
					require.NoError(test, err)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					hash, err := powValueTypes.NewHashWithName(sha256.New(), "SHA-256")
					require.NoError(test, err)

					challenge, err := pow.NewChallengeBuilder().
						SetLeadingZeroBitCount(leadingZeroBitCount).
						SetCreatedAt(createdAt).
						SetTTL(ttl).
						SetResource(powValueTypes.NewResource(&url.URL{
							Scheme: "https",
							Host:   "example.com",
							Path:   "/",
						})).
						SetSerializedPayload(powValueTypes.NewSerializedPayload("dummy")).
						SetHash(hash).
						SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
							"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
								":{{ .Challenge.SerializedPayload.ToString }}" +
								":{{ .Nonce.ToString }}",
						)).
						Build()
					require.NoError(test, err)

					return challenge
				}(),
			},
			want: Challenge{
				LeadingZeroBitCount: 5,
				CreatedAt:           "2000-01-02T03:04:05.000000006Z",
				TTL:                 "876000h0m0s",
				Resource:            "https://example.com/",
				Payload:             "dummy",
				HashName:            "SHA-256",
				HashDataLayout: "{{.Challenge.LeadingZeroBitCount.ToInt}}" +
					":{{.Challenge.SerializedPayload.ToString}}" +
					":{{.Nonce.ToString}}",
			},
			wantErr: assert.NoError,
		},
		{
			name: "error/`CreatedAt` timestamp is required",
			args: args{
				entity: func() pow.Challenge {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					hash, err := powValueTypes.NewHashWithName(sha256.New(), "SHA-256")
					require.NoError(test, err)

					challenge, err := pow.NewChallengeBuilder().
						SetLeadingZeroBitCount(leadingZeroBitCount).
						SetResource(powValueTypes.NewResource(&url.URL{
							Scheme: "https",
							Host:   "example.com",
							Path:   "/",
						})).
						SetSerializedPayload(powValueTypes.NewSerializedPayload("dummy")).
						SetHash(hash).
						SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
							"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
								":{{ .Challenge.SerializedPayload.ToString }}" +
								":{{ .Nonce.ToString }}",
						)).
						Build()
					require.NoError(test, err)

					return challenge
				}(),
			},
			want:    Challenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/resource is required",
			args: args{
				entity: func() pow.Challenge {
					leadingZeroBitCount, err := powValueTypes.NewLeadingZeroBitCount(5)
					require.NoError(test, err)

					createdAt, err := powValueTypes.NewCreatedAt(
						time.Date(2000, time.January, 2, 3, 4, 5, 6, time.UTC),
					)
					require.NoError(test, err)

					ttl, err := powValueTypes.NewTTL(100 * 365 * 24 * time.Hour)
					require.NoError(test, err)

					hash, err := powValueTypes.NewHashWithName(sha256.New(), "SHA-256")
					require.NoError(test, err)

					challenge, err := pow.NewChallengeBuilder().
						SetLeadingZeroBitCount(leadingZeroBitCount).
						SetCreatedAt(createdAt).
						SetTTL(ttl).
						SetSerializedPayload(powValueTypes.NewSerializedPayload("dummy")).
						SetHash(hash).
						SetHashDataLayout(powValueTypes.MustParseHashDataLayout(
							"{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
								":{{ .Challenge.SerializedPayload.ToString }}" +
								":{{ .Nonce.ToString }}",
						)).
						Build()
					require.NoError(test, err)

					return challenge
				}(),
			},
			want:    Challenge{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got, err := NewChallengeFromEntity(data.args.entity)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}

func TestParseChallengeFromQuery(test *testing.T) {
	type args struct {
		query string
	}

	for _, data := range []struct {
		name    string
		args    args
		want    Challenge
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			args: args{
				query: "created-at=2000-01-02T03%3A04%3A05.000000006Z" +
					"&hash-data-layout=" +
					"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
					"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
					"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
					"&hash-name=SHA-256" +
					"&leading-zero-bit-count=5" +
					"&payload=dummy" +
					"&resource=https%3A%2F%2Fexample.com%2F" +
					"&ttl=876000h0m0s",
			},
			want: Challenge{
				LeadingZeroBitCount: 5,
				CreatedAt:           "2000-01-02T03:04:05.000000006Z",
				TTL:                 "876000h0m0s",
				Resource:            "https://example.com/",
				Payload:             "dummy",
				HashName:            "SHA-256",
				HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
					":{{ .Challenge.SerializedPayload.ToString }}" +
					":{{ .Nonce.ToString }}",
			},
			wantErr: assert.NoError,
		},
		{
			name: "error/unable to parse the query",
			args: args{
				query: "%",
			},
			want:    Challenge{},
			wantErr: assert.Error,
		},
		{
			name: "error/unable to construct the challenge from the values",
			args: args{
				query: "leading-zero-bit-count=invalid",
			},
			want:    Challenge{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got, err := ParseChallengeFromQuery(data.args.query)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}

func TestChallenge_ToQuery(test *testing.T) {
	type fields struct {
		LeadingZeroBitCount int
		CreatedAt           string
		TTL                 string
		Resource            string
		Payload             string
		HashName            string
		HashDataLayout      string
	}

	for _, data := range []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "success",
			fields: fields{
				LeadingZeroBitCount: 5,
				CreatedAt:           "2000-01-02T03:04:05.000000006Z",
				TTL:                 "876000h0m0s",
				Resource:            "https://example.com/",
				Payload:             "dummy",
				HashName:            "SHA-256",
				HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
					":{{ .Challenge.SerializedPayload.ToString }}" +
					":{{ .Nonce.ToString }}",
			},
			want: "created-at=2000-01-02T03%3A04%3A05.000000006Z" +
				"&hash-data-layout=" +
				"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
				"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
				"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
				"&hash-name=SHA-256" +
				"&leading-zero-bit-count=5" +
				"&payload=dummy" +
				"&resource=https%3A%2F%2Fexample.com%2F" +
				"&ttl=876000h0m0s",
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			model := Challenge{
				LeadingZeroBitCount: data.fields.LeadingZeroBitCount,
				CreatedAt:           data.fields.CreatedAt,
				TTL:                 data.fields.TTL,
				Resource:            data.fields.Resource,
				Payload:             data.fields.Payload,
				HashName:            data.fields.HashName,
				HashDataLayout:      data.fields.HashDataLayout,
			}
			got := model.ToQuery()

			assert.Equal(test, data.want, got)
		})
	}
}
