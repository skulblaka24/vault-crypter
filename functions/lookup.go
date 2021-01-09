package functions

import (
	"os"
	"fmt"
	"time"
	"sort"
	"bufio"
	"strings"
	"encoding/json"
	"github.com/mitchellh/cli"
	"github.com/ryanuber/columnize"
)


type VaultUI struct {
	cli.Ui
	format string
}

// Used for the lookup ouput function
const (
	// hopeDelim is the delimiter to use when splitting columns. We call it a
	// hopeDelim because we hope that it's never contained in a secret.
	hopeDelim = "♨"
)

func LookupToken(vault_token string, useColor bool){

	// Waits a second in case, we generated the token from a secondary node.
	time.Sleep(1 * time.Second)

	// Get the token infos
	lookup, err := vault_client.Auth().Token().Lookup(vault_token)
	if err != nil {
		Error("main", "\n"+err.Error(), useColor, "1")
	}

	formatOutput(lookup.Data)
}

// Used for the lookup ouput function
func looksLikeDuration(k string) bool {
	return k == "period" || strings.HasSuffix(k, "_period") ||
		k == "ttl" || strings.HasSuffix(k, "_ttl") ||
		k == "duration" || strings.HasSuffix(k, "_duration") ||
		k == "lease_max" || k == "ttl_max"
}

// Used for the lookup ouput function
// humanDuration prints the time duration without those pesky zeros.
func humanDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}

	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if idx := strings.Index(s, "h0m"); idx > 0 {
		s = s[:idx+1] + s[idx+3:]
	}
	return s
}

// Used for the lookup ouput function
// humanDurationInt prints the given int as if it were a time.Duration  number
// of seconds.
func humanDurationInt(i interface{}) interface{} {
	switch i.(type) {
	case int:
		return humanDuration(time.Duration(i.(int)) * time.Second)
	case int64:
		return humanDuration(time.Duration(i.(int64)) * time.Second)
	case json.Number:
		if i, err := i.(json.Number).Int64(); err == nil {
			return humanDuration(time.Duration(i) * time.Second)
		}
	}

	// If we don't know what type it is, just return the original value
	return i
}

// Used for the lookup ouput function
func tableOutput(list []string, c *columnize.Config) string {
	if len(list) == 0 {
		return ""
	}

	delim := "|"
	if c != nil && c.Delim != "" {
		delim = c.Delim
	}

	underline := ""
	headers := strings.Split(list[0], delim)
	for i, h := range headers {
		h = strings.TrimSpace(h)
		u := strings.Repeat("-", len(h))

		underline = underline + u
		if i != len(headers)-1 {
			underline = underline + delim
		}
	}

	list = append(list, "")
	copy(list[2:], list[1:])
	list[1] = underline

	return columnOutput(list, c)
}

// Used for the lookup ouput function
// columnOuput prints the list of items as a table with no headers.
func columnOutput(list []string, c *columnize.Config) string {
	if len(list) == 0 {
		return ""
	}

	if c == nil {
		c = &columnize.Config{}
	}
	if c.Glue == "" {
		c.Glue = "    "
	}
	if c.Empty == "" {
		c.Empty = "n/a"
	}

	return columnize.Format(list, c)
}

// Used for the lookup ouput function
func formatOutput(data map[string]interface{}){
	out := make([]string, 0, len(data)+1)
	if len(data) > 0 {
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			v := data[k]

			// If the field "looks" like a TTL, print it as a time duration instead.
			if looksLikeDuration(k) {
				v = humanDurationInt(v)
			}

			out = append(out, fmt.Sprintf("%s %s %v", k, hopeDelim, v))
		}
	}

	// If we got this far and still don't have any data, there's nothing to print,
	// sorry.
	if len(out) == 0 {
		os.Exit(1)
	}

	// Prepend the header
	out = append([]string{"Key" + hopeDelim + "Value"}, out...)

	ui := &VaultUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader:      bufio.NewReader(os.Stdin),
				Writer:      os.Stdout,
				ErrorWriter: os.Stderr,
			},
		},
		format: "table",
	}

	ui.Output(tableOutput(out, &columnize.Config{
		Delim: hopeDelim,
	}))
}