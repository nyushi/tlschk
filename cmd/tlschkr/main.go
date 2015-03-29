package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/nyushi/tlschk"
)

var (
	isV4     = flag.Bool("4", false, "use ipv4")
	isV6     = flag.Bool("6", false, "use ipv6")
	startTLS = flag.Bool("starttls", false, "use STARTTLS")
	trust    = flag.Bool("trust", false, "ignore all certificate verification error")
	days     = flag.Int64("days", 30, "number of certificate remaining days")
)

func getPort(in string) int {
	port, _ := strconv.Atoi(in)
	if port == 0 {
		port = 443
	}
	return port
}

func getConfig(host string, port int) *tlschk.Config {
	c := tlschk.NewDefaultConfig()
	c.Connect.Address = host
	c.Connect.Port = port

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
		var rt float64 = 5
		c.PlainRoundTrip.Send = &send
		c.PlainRoundTrip.Timeout = &rt
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
	//host, port, err := getHostPort(flag.Arg(0))
	host := flag.Arg(0)
	port := getPort(flag.Arg(1))

	var result *tlschk.Result
	if host == "" {
		result = tlschk.DoCheck(os.Stdin)
	} else {
		c := getConfig(host, port)
		result = tlschk.DoCheckByConfig(c)
	}
	outBytes, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("%s", outBytes)
}
