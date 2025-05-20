package tracer

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var aaaResponseOrfAtPayload = []byte{
	0xaa, 0x75, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61,
	0x74, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x29,
	0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00,
	0x0a, 0x00, 0x08, 0x8a, 0xd4, 0x77, 0xb5, 0xd4,
	0xdb, 0x3e, 0xb2,
}

func TestParseDNSMessage(t *testing.T) {
	type testCase struct {
		title          string
		packetData     []byte
		expectedParsed parsedDnsMsg
		expectedErr    error
	}

	testCases := []testCase{
		{
			title:      "parse AAAA success response",
			packetData: aaaResponseOrfAtPayload,
			expectedParsed: parsedDnsMsg{
				transactionID: 43637,
				questionType:  "AAAA",
				name:          "orf.at.",
				resultCode:    "Success",
			},
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			result, err := parseDNSMessage(tc.packetData)
			if tc.expectedErr != nil {
				if !errors.Is(err, tc.expectedErr) {
					t.Fatalf("expected err `%v`, but got `%v`", tc.expectedErr, err)
				}
				return
			}

			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			diffStr := cmp.Diff(result, tc.expectedParsed, cmp.AllowUnexported(parsedDnsMsg{}))
			if diffStr != "" {
				t.Fatalf("did not get expected result:\n%s", diffStr)
			}
		})
	}
}
