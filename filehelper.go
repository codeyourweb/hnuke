package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/k3a/html2text"
	"github.com/ledongthuc/pdf"
)

// RetrivesFilesFromUserPath return a []string of available files from given path
func RetrivesFilesFromUserPath(path string, includeFileExtensions []string, recursive bool) ([]string, error) {
	var p []string

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return []string{}, errors.New("Input file not found")
	}

	if !info.IsDir() {
		p = append(p, path)
	} else {
		if !recursive {
			files, err := ioutil.ReadDir(path)
			if err != nil {
				return []string{}, err
			}
			for _, f := range files {
				if !f.IsDir() {
					p = append(p, path+string(os.PathSeparator)+f.Name())
				}
			}
		} else {
			err := filepath.Walk(path, func(walk string, info os.FileInfo, err error) error {
				if err != nil {
					log.Println(err)
				}

				if err == nil && !info.IsDir() && info.Size() > 0 && len(filepath.Ext(walk)) > 0 && (len(includeFileExtensions) == 0 || StringInSlice(filepath.Ext(walk), includeFileExtensions)) {
					p = append(p, walk)
				}

				return nil
			})

			if err != nil {
				log.Println(err)
			}
		}
	}

	return p, nil
}

// ExtractHashFromFile return an array of hash parsed from a given file
func ExtractHashFromFile(path string) ([]string, error) {
	var fileContent string
	var buffer []byte
	var err error

	buffer, err = ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	contentType := http.DetectContentType(buffer)

	switch strings.Split(contentType, ";")[0] {
	case "application/pdf":
		fileContent, err = ReadPlainTextFromPDF(path)
		if err != nil {
			return []string{}, err
		}
	default:
		fileContent = string(buffer)
	}

	return extractHashFromString(fileContent), nil
}

// ExtractHashFromURL try to get an HTML page, convert it to text and return an array of extracted hashs
func ExtractHashFromURL(url string) ([]string, error) {
	var req *http.Request
	var res *http.Response
	var body []byte
	var err error

	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return []string{}, err
	}
	req.Header.Set("User-Agent", USERAGENT)
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: time.Second * HTTPTIMEOUT}
	res, err = client.Do(req)
	if err != nil {
		return []string{}, err
	}
	defer res.Body.Close()

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return []string{}, err
	}

	plain := html2text.HTML2Text(string(body))

	return extractHashFromString(plain), nil
}

func extractHashFromString(content string) []string {
	r := regexp.MustCompile(`(?i)([0-9a-f]{32,64})`)
	return r.FindAllString(content, -1)
}

// ReadPlainTextFromPDF extract text from PDF File
func ReadPlainTextFromPDF(pdfpath string) (text string, err error) {
	f, r, err := pdf.Open(pdfpath)
	defer f.Close()
	if err != nil {
		return
	}

	var buf bytes.Buffer
	b, err := r.GetPlainText()
	if err != nil {
		return
	}

	buf.ReadFrom(b)
	text = buf.String()
	return
}

// UniqueSliceMembers Remove duplicate case insensitive entries inside the specified slice
func UniqueSliceMembers(in []string) []string {
	var buffer []string
	for _, o := range in {
		if !StringInSlice(strings.ToLower(o), buffer) {
			buffer = append(buffer, strings.ToLower(o))
		}
	}
	return buffer
}

// StringInSlice check wether or not a string already is inside a specified slice
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// HashContentFromFile return the sha1sum of the specified file
func HashContentFromFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}

	defer file.Close()

	return sha1FromStream(file)
}

// HashContentFromURL return the sha1sum of the specified web content
func HashContentFromURL(url string) (string, error) {
	var req *http.Request
	var res *http.Response
	var err error

	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", USERAGENT)
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: time.Second * HTTPTIMEOUT}
	res, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	return sha1FromStream(res.Body)

}

func sha1FromStream(stream io.Reader) (string, error) {
	hash := sha1.New()
	if _, err := io.Copy(hash, stream); err != nil {
		return "", err
	}

	hashInBytes := hash.Sum(nil)[:20]
	return hex.EncodeToString(hashInBytes), nil
}
