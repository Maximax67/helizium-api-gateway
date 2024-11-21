package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/krakendio/bloomfilter/v2/rpc/client"
)

func main() {
	server := flag.String("server", "krakend:1234", "ip:port of the remote bloomfilter to connect to")
	key := flag.String("key", "jti", "the name of the claim to inspect for revocations")
	port := flag.Int("port", 8080, "port to expose the service")
	flag.Parse()

	var err error
	var c *client.Bloomfilter

	c, err = tryToConnectToBloomFilter(c, *server)
	if err != nil {
		log.Println("Unable to create the RPC client:", err.Error())
		return
	}
	defer c.Close()

	tmpl, parseErr := template.ParseFiles("./static/index.html")
	if parseErr != nil {
		log.Fatalf("Error parsing template: %v", err)
	}

	http.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		r.ParseForm()
		jtiList := r.FormValue(*key)
		if jtiList == "" {
			http.Error(w, "No jti provided", http.StatusBadRequest)
			return
		}

		jtis := strings.Split(jtiList, ",")
		for _, jti := range jtis {
			jti = strings.TrimSpace(jti)
			if jti == "" {
				continue
			}

			subject := *key + "-" + jti
			c, _ = addToBloomFilter(c, subject, *server, w)
		}

		w.WriteHeader(http.StatusNoContent)
	})

	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		subject := *key + "-" + r.FormValue(*key)

		var res bool
		var err error
		c, res, err = checkInBloomFilter(c, subject, *server, w)
		if err == nil {
			fmt.Fprintf(w, "%v", res)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Add("Content-Type", "text/html")
		tmpl.Execute(rw, *key)
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}

func addToBloomFilter(c *client.Bloomfilter, subject, server string, w http.ResponseWriter) (*client.Bloomfilter, error) {
	if err := c.Add([]byte(subject)); err != nil {
		c, err := tryToConnectToBloomFilter(c, server)
		if err != nil {
			log.Printf("Error connecting to Bloom filter %s: %v", subject, err)
			http.Error(w, "Failed to connect to bloom filter", http.StatusInternalServerError)
			return nil, err
		}

		if err := c.Add([]byte(subject)); err != nil {
			log.Printf("Error adding %s: %v", subject, err)
			http.Error(w, "Failed to add to bloom filter", http.StatusInternalServerError)
			return nil, err
		}
	}

	log.Printf("Added -> %s", subject)

	return c, nil
}

func checkInBloomFilter(c *client.Bloomfilter, subject, server string, w http.ResponseWriter) (*client.Bloomfilter, bool, error) {
	res, err := c.Check([]byte(subject))
	if err != nil {
		c, err = tryToConnectToBloomFilter(c, server)
		if err != nil {
			log.Printf("Error connecting to Bloom filter %s: %v", subject, err)
			http.Error(w, "Failed to connect to bloom filter", http.StatusInternalServerError)
			return c, false, err
		}

		res, err = c.Check([]byte(subject))
		if err != nil {
			log.Printf("Error checking %s: %v", subject, err)
			http.Error(w, "Failed to check in bloom filter", http.StatusInternalServerError)
			return c, false, err
		}
	}

	log.Printf("Checked %s -> %v", subject, res)

	return c, res, nil
}

func tryToConnectToBloomFilter(c *client.Bloomfilter, server string) (*client.Bloomfilter, error) {
	if c != nil {
		c.Close()
	}

	var err error
	for i := 1; i < 6; i++ {
		c, err = client.New(server)
		if err == nil {
			return c, nil
		}

		log.Printf("Failed to connect to server: %v. Retrying in %d seconds...", err, i)
		time.Sleep(time.Duration(i) * time.Second)
	}

	return c, err
}
