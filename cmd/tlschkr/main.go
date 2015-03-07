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

var (
	isV4     = flag.Bool("4", false, "use ipv4")
	isV6     = flag.Bool("6", false, "use ipv6")
	startTLS = flag.Bool("starttls", false, "use STARTTLS")
	trust    = flag.Bool("trust", false, "ignore all certificate verification error")
	days     = flag.Int64("days", 30, "number of certificate remaining days")
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

func getConfig(host string, port int) *tlschk.Config {
	c := tlschk.NewDefaultConfig()
	c.Connect.Address = &host
	c.Connect.Port = &port

	c.Handshake.CheckServername = &host

	if *isV4 {
		var v int64 = 4
		c.Connect.IPVersion = &v
	}
	if *isV6 {
		var v int64 = 6
		c.Connect.IPVersion = &v
	}
	if *startTLS {
		send := "STARTTLS\r\n"
		var rt int64 = 5
		c.PlainRoundTrip.Send = &send
		c.PlainRoundTrip.ReadTimeout = &rt
	}
	if *trust {
		b := false
		c.Handshake.CheckTrustedByRoot = &b
		c.Handshake.CheckRevocation = &b
		c.Handshake.CheckServername = nil
	}

	c.Handshake.CheckNotAfterRemains = days
	return c
}

func main() {
	flag.Parse()
	host, port, err := getHostPort(flag.Arg(0))
	var result *tlschk.Result
	if err != nil {
		result = tlschk.DoCheck(os.Stdin)
	} else {
		c := getConfig(host, port)
		result = tlschk.DoCheckByConfig(c)
	}
	outBytes, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("%s", outBytes)
}
