package model_test

import (
	"testing"

	"github.com/pHo9UBenaA/osv-report/internal/model"
)

func TestModifiedCSVURL_EcosystemVariants(t *testing.T) {
	cases := []struct {
		name    string
		eco     model.Ecosystem
		wantURL string
	}{
		{
			name:    "SimpleEcosystem_ReturnsDirectPath",
			eco:     model.NPM,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
		},
		{
			name:    "EcosystemWithSpace_PercentEncodesSpace",
			eco:     model.GitHubActions,
			wantURL: "https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.eco.ModifiedCSVURL()
			if got != tt.wantURL {
				t.Errorf("ModifiedCSVURL() = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

func TestSitemapURL_EcosystemVariants(t *testing.T) {
	cases := []struct {
		name    string
		eco     model.Ecosystem
		wantURL string
	}{
		{
			name:    "SimpleEcosystem_ReturnsUnmodifiedName",
			eco:     model.NPM,
			wantURL: "https://osv.dev/sitemap_npm.xml",
		},
		{
			name:    "EcosystemWithSpace_ReplacesSpaceWithUnderscore",
			eco:     model.GitHubActions,
			wantURL: "https://osv.dev/sitemap_GitHub_Actions.xml",
		},
		{
			name:    "EcosystemWithHyphen_PreservesHyphen",
			eco:     model.OSSFuzz,
			wantURL: "https://osv.dev/sitemap_OSS-Fuzz.xml",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.eco.SitemapURL()
			if got != tt.wantURL {
				t.Errorf("SitemapURL() = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

func TestValidateEcosystems_BatchValidation(t *testing.T) {
	allowList := []string{"npm", "PyPI", "Go"}

	cases := []struct {
		name       string
		ecosystems []model.Ecosystem
		wantErr    bool
	}{
		{
			name:       "AllValid_ReturnsNil",
			ecosystems: []model.Ecosystem{model.NPM, model.PyPI, model.Go},
			wantErr:    false,
		},
		{
			name:       "OneInvalid_ReturnsError",
			ecosystems: []model.Ecosystem{model.NPM, model.Ecosystem("Unknown")},
			wantErr:    true,
		},
		{
			name:       "MultipleInvalid_ReturnsJoinedError",
			ecosystems: []model.Ecosystem{model.Ecosystem("A"), model.Ecosystem("B")},
			wantErr:    true,
		},
		{
			name:       "Empty_ReturnsNil",
			ecosystems: []model.Ecosystem{},
			wantErr:    false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := model.ValidateEcosystems(tt.ecosystems, allowList)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEcosystems() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseEcosystems_InputVariants(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []model.Ecosystem
	}{
		{
			name:  "CommaSeparatedList_ReturnsParsedSlice",
			input: "npm,PyPI,Go",
			want:  []model.Ecosystem{model.NPM, model.PyPI, model.Go},
		},
		{
			name:  "WhitespaceAroundEntries_TrimsAndParses",
			input: " npm , PyPI , Go ",
			want:  []model.Ecosystem{model.NPM, model.PyPI, model.Go},
		},
		{
			name:  "EmptyString_ReturnsEmptySlice",
			input: "",
			want:  []model.Ecosystem{},
		},
		{
			name:  "AnyValue_ParsedWithoutValidation",
			input: "npm,InvalidEco,PyPI",
			want:  []model.Ecosystem{model.NPM, model.Ecosystem("InvalidEco"), model.PyPI},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := model.ParseEcosystems(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("ParseEcosystems() got %d ecosystems, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseEcosystems()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
