package codvn

import "testing"

var testCases = []struct {
	title  string
	hashed string
	clear  string
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
}

func TestVerify(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			c, err := Parse([]byte(tc.hashed))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Verify([]byte(tc.clear)); err != nil {
				t.Error(err)
			}
			if c.String() != tc.hashed {
				t.Errorf("got %v, want %v", c, tc.hashed)
			}
		})
	}
}

func BenchmarkSHA(b *testing.B) {
	for _, tc := range testCases {
		b.Run(tc.title, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				Verify([]byte(tc.hashed), []byte(tc.clear))
			}
		})
	}
}
