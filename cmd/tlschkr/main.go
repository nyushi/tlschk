package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/nyushi/tlschk"
)

func getHostPort(in string) (string, int, error) {
	if in == "" {
		return "", 0, errors.New("invalid input")
	}
	if !strings.Contains(in, ":") {
		return in, 443, nil
	}
	host, portStr, err := net.SplitHostPort(in)
	if err != nil {
		return "", 0, err
	}
	port, _ := strconv.Atoi(portStr)
	return host, port, nil
}

func main() {
	flag.Parse()
	host, port, err := getHostPort(flag.Arg(0))
	var result *tlschk.Result
	if err != nil {
		result = tlschk.DoCheck(os.Stdin)
	} else {
		j := fmt.Sprintf(`{"connect": {"address": "%s", "port": %d}}`, host, port)
		r := strings.NewReader(j)
		result = tlschk.DoCheck(r)
	}
	outBytes, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("%s", outBytes)
}
