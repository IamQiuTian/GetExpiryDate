package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/likexian/whois-go"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	conf    *string
	threads *int
	ssl     *bool
	domain  *bool
	counter chan bool
	wg      sync.WaitGroup
)

func init() {
	conf = flag.String("f", "Default.conf", "Specify profile")
	threads = flag.Int("t", 1, "Number of threads")
	ssl = flag.Bool("s", false, "Displays the certificate expiration date")
	domain = flag.Bool("d", false, "Displays domain name expiration date")
	flag.Parse()
	counter = make(chan bool, *threads)
	if *ssl && *domain {
		log.Fatal("Simultaneous display is not currently supported")
	} else if !*ssl && !*domain {
		log.Fatal("Please choose at least one")
	}
}

func GetDomainExpiryDate(domain string) (float64, error) {
	result, err := whois.Whois(domain)
	if err != nil {
		return float64(000.000), err
	}
	if !strings.Contains(result, "Registry Expiry Date") {
		return float64(000.000), fmt.Errorf("This domain name is not registered")
	}
	re := regexp.MustCompile(`Registry Expiry Date:\s\d+-\d+-\d+`)
	domainExpiryDate := strings.Split(re.FindString(result), ":")[1]
	domainExpiryDate = strings.TrimSpace(domainExpiryDate)
	domainExpiryDateTime, _ := time.Parse("2006-01-02", domainExpiryDate)
	domainTimeRemaining := domainExpiryDateTime.Sub(time.Now()) / 24

	return FloatRound(domainTimeRemaining.Hours(), 0), nil
}

func GetSSLExpiryDate(domain string) (float64, error) {
	dialer := net.Dialer{Timeout: time.Second * 5}
	conn, err := tls.DialWithDialer(&dialer, "tcp", fmt.Sprintf("%s:%d", domain, 443), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return float64(000.000), err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	sslExpiryDateTime := state.PeerCertificates[0].NotAfter
	sslTimeRemaining := sslExpiryDateTime.Sub(time.Now()).Hours() / 24

	return FloatRound(sslTimeRemaining, 0), nil
}

func FloatRound(f float64, n int) float64 {
	format := "%." + strconv.Itoa(n) + "f"
	res, _ := strconv.ParseFloat(fmt.Sprintf(format, f), 64)
	return res
}

func DomainCheck(domain string) bool {
	var match bool
	IsLine := "^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}(/)"
	NotLine := "^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}"
	match, _ = regexp.MatchString(IsLine, domain)
	if !match {
		match, _ = regexp.MatchString(NotLine, domain)
	}
	return match
}

func run(conf string) {
	f, err := os.Open(conf)
	if err != nil {
		log.Fatal(err)
	}
	reader := bufio.NewScanner(f)
	for reader.Scan() {
		domname := reader.Text()
		if len(domname) == 0 {
			return
		}
		if !DomainCheck(domname) {
			return
		}
		counter <- true
		wg.Add(1)
		if *ssl {
			go func() {
				defer wg.Done()
				defer func() { <-counter }()
				SSLRes, err := GetSSLExpiryDate(domname)
				if err != nil {
					fmt.Println(domname, " ", err)
					return
				}
				fmt.Println(domname, " SSL证书还有 ", SSLRes, "天过期")
			}()
		} else if *domain {
			go func() {
				defer wg.Done()
				defer func() { <-counter }()
				DomainRes, err := GetDomainExpiryDate(domname)
				if err != nil {
					fmt.Println(domname, " ", err)
					return
				}
				fmt.Println(domname, " 域名还有 ", DomainRes, " 天过期")
			}()
		}
	}
	defer f.Close()
	defer close(counter)
	wg.Wait()
}

func main() {
	run(*conf)
}
