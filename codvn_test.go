package codvn

import "testing"

var testCases = []struct {
	title  string
	hashed string
	clear  string
	perr   error // parse error
	verr   error // verify error
}{
	{
		title:  "sha1",
		hashed: `{x-issha,1024}IlU5JC/UaAzvUl8ncaxIBlFQ1Nfd0C5YxkizRFg970g=`,
		clear:  `Pindakaas!`,
	},
	{
		title:  "sha256",
		hashed: `{x-isSHA256,10000}MMuaPcoQH1RbzPUdV3/kjNsG27X6UYILSCW8yDSD70skvasBGNvXXhFPKJcWKmDS`,
		clear:  `HashCat!`,
	},
	{
		title:  "sha384",
		hashed: `{x-isSHA384,7500}kqOPN/VxvZXpD8zEiRBAe1L6fW6GTXRd/RFl0AbaEbyCZFeMBA8+NKV6MG2Me2u3ZRlCdflPuccjtr55`,
		clear:  `HashCat!`,
	},
	{
		title:  "sha512",
		hashed: `{x-isSHA512,15000}lbaY7cwziH2rPfBdr9T3mZKT/DMXstwSzT1mXNipjYxqoIXfmKBIrcfSNkwq/S5DbqtrDCKX7iOnzPhnIyXRitydEZPrB/BseZ799wYL2O0=`,
		clear:  `testtest`,
	},
	{
		title: "empty",
		perr:  ErrTruncatedInput,
	},
	{
		title:  "truncated",
		hashed: `{x-issha,1024}Cg==`,
		perr:   ErrTruncatedInput,
	},
	{
		title:  "zero",
		hashed: `{x-issha,0}IlU5JC/UaAzvUl8ncaxIBlFQ1Nfd0C5YxkizRFg970g=`,
		perr:   ErrZeroIterations,
	},
	{
		title:  "kind",
		hashed: `{x-ismd5,1024}IlU5JC/UaAzvUl8ncaxIBlFQ1Nfd0C5YxkizRFg970g=`,
		perr:   ErrUnknownHash,
	},
	{
		title:  "verify",
		hashed: `{x-issha,1024}IlU5JC/UaAzvUl8ncaxIBlFQ1Nfd0C5YxkizRFg970g=`,
		verr:   ErrDontMatch,
	},
}

func TestCodvN(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			c, err := Parse([]byte(tc.hashed))
			if err != tc.perr {
				t.Fatalf("got %v, want %v", err, tc.perr)
			}
			if tc.perr != nil {
				return
			}
			if err := c.Verify([]byte(tc.clear)); err != tc.verr {
				t.Fatalf("got %v, want %v", err, tc.verr)
			}
			if tc.verr != nil {
				return
			}
			if c.String() != tc.hashed {
				t.Errorf("got %v, want %v", c, tc.hashed)
			}
		})
	}
}

func BenchmarkCodvN(b *testing.B) {
	for _, tc := range testCases {
		if tc.perr != nil || tc.verr != nil {
			continue
		}
		b.Run(tc.title, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				Verify([]byte(tc.hashed), []byte(tc.clear))
			}
		})
	}
}
