// Deliberate-bad sample file for cyscan integration tests.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
)

func run() {
	cfg := &tls.Config{InsecureSkipVerify: true} // CBR-GO-TLS-INSECURE-SKIP-VERIFY
	fmt.Println(cfg, md5.New())                   // CBR-GO-WEAK-HASH
}
