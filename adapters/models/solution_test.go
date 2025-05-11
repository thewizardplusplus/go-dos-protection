package dosProtectorAdapterModels

import (
	"crypto/sha256"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pow "github.com/thewizardplusplus/go-pow"
	powValueTypes "github.com/thewizardplusplus/go-pow/value-types"
)

func TestNewSolutionFromEntity(test *testing.T) {
	type args struct {
		entity pow.Solution
	}

	for _, data := range []struct {
		name    string
		args    args
		want    Solution
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success/with a hash sum",
			args: args{
				entity: func() pow.Solution {
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

					nonce, err := powValueTypes.NewNonce(big.NewInt(37))
					require.NoError(test, err)

					solution, err := pow.NewSolutionBuilder().
						SetChallenge(challenge).
						SetNonce(nonce).
						SetHashSum(powValueTypes.NewHashSum([]byte{
							0x00, 0x5d, 0x37, 0x2c, 0x56, 0xe6, 0xc6, 0xb5,
							0x2a, 0xd4, 0xa8, 0x32, 0x56, 0x54, 0x69, 0x2e,
							0xc9, 0xaa, 0x3a, 0xf5, 0xf7, 0x30, 0x21, 0x74,
							0x8b, 0xc3, 0xfd, 0xb1, 0x24, 0xae, 0x9b, 0x20,
						})).
						Build()
					require.NoError(test, err)

					return solution
				}(),
			},
			want: Solution{
				Challenge: Challenge{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{.Challenge.LeadingZeroBitCount.ToInt}}" +
						":{{.Challenge.SerializedPayload.ToString}}" +
						":{{.Nonce.ToString}}",
				},

				Nonce: "37",
				HashSum: mo.Some(
					"005d372c56e6c6b5" +
						"2ad4a8325654692e" +
						"c9aa3af5f7302174" +
						"8bc3fdb124ae9b20",
				),
			},
			wantErr: assert.NoError,
		},
		{
			name: "success/without a hash sum",
			args: args{
				entity: func() pow.Solution {
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

					nonce, err := powValueTypes.NewNonce(big.NewInt(37))
					require.NoError(test, err)

					solution, err := pow.NewSolutionBuilder().
						SetChallenge(challenge).
						SetNonce(nonce).
						Build()
					require.NoError(test, err)

					return solution
				}(),
			},
			want: Solution{
				Challenge: Challenge{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{.Challenge.LeadingZeroBitCount.ToInt}}" +
						":{{.Challenge.SerializedPayload.ToString}}" +
						":{{.Nonce.ToString}}",
				},

				Nonce:   "37",
				HashSum: mo.None[string](),
			},
			wantErr: assert.NoError,
		},
		{
			name: "error",
			args: args{
				entity: func() pow.Solution {
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

					nonce, err := powValueTypes.NewNonce(big.NewInt(37))
					require.NoError(test, err)

					solution, err := pow.NewSolutionBuilder().
						SetChallenge(challenge).
						SetNonce(nonce).
						SetHashSum(powValueTypes.NewHashSum([]byte{
							0x00, 0x5d, 0x37, 0x2c, 0x56, 0xe6, 0xc6, 0xb5,
							0x2a, 0xd4, 0xa8, 0x32, 0x56, 0x54, 0x69, 0x2e,
							0xc9, 0xaa, 0x3a, 0xf5, 0xf7, 0x30, 0x21, 0x74,
							0x8b, 0xc3, 0xfd, 0xb1, 0x24, 0xae, 0x9b, 0x20,
						})).
						Build()
					require.NoError(test, err)

					return solution
				}(),
			},
			want:    Solution{},
			wantErr: assert.Error,
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			got, err := NewSolutionFromEntity(data.args.entity)

			assert.Equal(test, data.want, got)
			data.wantErr(test, err)
		})
	}
}

func TestSolution_ToQuery(test *testing.T) {
	type fields struct {
		Challenge Challenge
		Nonce     string
		HashSum   mo.Option[string]
	}

	for _, data := range []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "success/with a hash sum",
			fields: fields{
				Challenge: Challenge{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},

				Nonce: "37",
				HashSum: mo.Some(
					"005d372c56e6c6b5" +
						"2ad4a8325654692e" +
						"c9aa3af5f7302174" +
						"8bc3fdb124ae9b20",
				),
			},
			want: "created-at=2000-01-02T03%3A04%3A05.000000006Z" +
				"&hash-data-layout=" +
				"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
				"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
				"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
				"&hash-name=SHA-256" +
				"&hash-sum=" +
				"005d372c56e6c6b5" +
				"2ad4a8325654692e" +
				"c9aa3af5f7302174" +
				"8bc3fdb124ae9b20" +
				"&leading-zero-bit-count=5" +
				"&nonce=37" +
				"&payload=dummy" +
				"&resource=https%3A%2F%2Fexample.com%2F" +
				"&ttl=" + (100 * 365 * 24 * time.Hour).String(),
		},
		{
			name: "success/without a hash sum",
			fields: fields{
				Challenge: Challenge{
					LeadingZeroBitCount: 5,
					CreatedAt:           "2000-01-02T03:04:05.000000006Z",
					TTL:                 (100 * 365 * 24 * time.Hour).String(),
					Resource:            "https://example.com/",
					Payload:             "dummy",
					HashName:            "SHA-256",
					HashDataLayout: "{{ .Challenge.LeadingZeroBitCount.ToInt }}" +
						":{{ .Challenge.SerializedPayload.ToString }}" +
						":{{ .Nonce.ToString }}",
				},

				Nonce:   "37",
				HashSum: mo.None[string](),
			},
			want: "created-at=2000-01-02T03%3A04%3A05.000000006Z" +
				"&hash-data-layout=" +
				"%7B%7B+.Challenge.LeadingZeroBitCount.ToInt+%7D%7D" +
				"%3A%7B%7B+.Challenge.SerializedPayload.ToString+%7D%7D" +
				"%3A%7B%7B+.Nonce.ToString+%7D%7D" +
				"&hash-name=SHA-256" +
				"&leading-zero-bit-count=5" +
				"&nonce=37" +
				"&payload=dummy" +
				"&resource=https%3A%2F%2Fexample.com%2F" +
				"&ttl=" + (100 * 365 * 24 * time.Hour).String(),
		},
	} {
		test.Run(data.name, func(test *testing.T) {
			model := Solution{
				Challenge: data.fields.Challenge,
				Nonce:     data.fields.Nonce,
				HashSum:   data.fields.HashSum,
			}
			got := model.ToQuery()

			assert.Equal(test, data.want, got)
		})
	}
}
