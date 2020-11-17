package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/antonholmquist/jason"
)

// VTBASEURL define the VirusTotal API endpoint for hash requesting
const VTBASEURL = "https://www.virustotal.com/api/v3/files/"

// USERAGENT defines an existing UA instead of Golang one
const USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0"

// HTTPACCEPT defines what content type would be accepted
const HTTPACCEPT = "application/json,text/*;q=0.99"

// HTTPTIMEOUT defined the time exprimed in seconds for HTTP requests timeout
const HTTPTIMEOUT = 5

// DEFAULTSLEEPTIME is an integer value to generate time sleep in VirusTotal API receive a 429 HTTP code
const DEFAULTSLEEPTIME = 60

// APIERROR400 is the default error return message for HTTP 400 code
const APIERROR400 = "Bad request - if input file is a PDF maybe it's the result of an error on parsing"

// APIERROR401 is the default error return message for HTTP 401 code
const APIERROR401 = "Wrong VirusTotal API key - Cannot proceed"

// APIERROR404 is the default error return message for HTTP 404 code
const APIERROR404 = "Not found on VirusTotal"

// APIERROR429 is the default error return message for HTTP 429 code
const APIERROR429 = "VirusTotal API request rate reached : sleeping some time..."

// GetHashInformations parse retrieves relevant information on a specific md5/sha1/sha256 hash with VirusTotal API
func GetHashInformations(hash string, VTkey string) (VTResult, error) {
	var req *http.Request
	var res *http.Response
	var body []byte
	var err error

	req, err = http.NewRequest("GET", VTBASEURL+hash, nil)
	if err != nil {
		return VTResult{}, err
	}
	req.Header.Set("x-apikey", VTkey)
	req.Header.Set("User-Agent", USERAGENT)
	req.Header.Set("Accept", HTTPACCEPT)

	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: time.Second * HTTPTIMEOUT}
	res, err = client.Do(req)

	if err != nil {
		return VTResult{}, err
	}

	defer res.Body.Close()

	switch res.StatusCode {
	case 400:
		log.Println(hash, APIERROR400)
		return VTResult{}, nil
	case 401:
		return VTResult{}, errors.New(APIERROR401)
	case 404:
		log.Println(hash, APIERROR404)
		return VTResult{}, nil
	case 429:
		log.Println(APIERROR429)
		time.Sleep(DEFAULTSLEEPTIME * time.Second)
		return GetHashInformations(hash, VTkey)
	case 200:
		if body, err = ioutil.ReadAll(res.Body); err != nil {
			return VTResult{}, nil
		}
		return ProcessVirusTotalResult(body)
	default:
		return VTResult{}, errors.New(hash + " Unhandled API status code: " + fmt.Sprintf("%d", res.StatusCode))
	}

}

// ProcessVirusTotalResult return VTResult structure after processing a raw VirusTotal HTTP Response
func ProcessVirusTotalResult(res []byte) (VTResult, error) {
	var json *jason.Object
	var r VTResult
	var err error

	json, err = jason.NewObjectFromBytes(res)
	if err != nil {
		return VTResult{}, err
	}

	r.id, _ = json.GetString("data", "id")
	r.Md5, _ = json.GetString("data", "attributes", "md5")
	r.Sha1, _ = json.GetString("data", "attributes", "sha1")
	r.Sha256, _ = json.GetString("data", "attributes", "sha256")
	r.VHash, _ = json.GetString("data", "attributes", "vhash")
	r.rawCreationDate, _ = json.GetInt64("data", "attributes", "creation_date")
	r.rawFirstSubmission, _ = json.GetInt64("data", "attributes", "first_submission_date")
	r.rawLastAnalysis, _ = json.GetInt64("data", "attributes", "last_analysis_date")
	r.Filename, _ = json.GetStringArray("data", "attributes", "names")
	r.rawFilesize, _ = json.GetInt64("data", "attributes", "size")
	r.FileType, _ = json.GetString("data", "attributes", "exiftool", "filetype")
	r.ImpHash, _ = json.GetString("data", "attributes", "pe_info", "imphash")
	r.MSDefender, _ = json.GetString("data", "attributes", "last_analysis_results", "Microsoft", "result")
	t1, _ := json.GetInt64("data", "attributes", "last_analysis_stats", "malicious")
	t2, _ := json.GetInt64("data", "attributes", "last_analysis_stats", "undetected")

	r.Statement = fmt.Sprintf("%d / %d", t1, t1+t2)

	r.FileSize = fmt.Sprintf("%.2fKB (%d bytes)", math.Round(float64(r.rawFilesize)/1024), r.rawFilesize)

	r.CreationDate = timestampToYMD(r.rawCreationDate)
	r.FirstSubmission = timestampToYMD(r.rawFirstSubmission)
	r.LastAnalysis = timestampToYMD(r.rawLastAnalysis)

	r.Tags, _ = json.GetStringArray("data", "attributes", "tags")
	r.URL = "https://www.virustotal.com/gui/file/" + r.id
	return r, nil
}

func timestampToYMD(timestamp int64) string {
	t := time.Unix(timestamp, 0)
	return fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}
