package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/akamensky/argparse"
	"github.com/schollz/progressbar"
)

func main() {
	var results []VTResult
	var buffer []string
	var hashs []string
	r := regexp.MustCompile("(?i)^https?://")

	// argparse

	parser := argparse.NewParser("hnuke", "Little handy tool to help hash analysis on VirusTotal (works with both VirusTotal free and entreprise API licence)")
	apikey := parser.String("a", "apikey", &argparse.Options{Required: true, Help: "VirusTotal API Key"})
	inFile := parser.String("i", "in", &argparse.Options{Required: true, Help: "Input file or directory"})
	outFile := parser.String("o", "out", &argparse.Options{Required: false, Help: "Save results to specified file - if not mentioned results will be printed to standard output"})
	format := parser.String("f", "format", &argparse.Options{Required: false, Default: "csv", Help: "Output format - csv | json supported"})
	mode := parser.String("m", "mode", &argparse.Options{Required: false, Default: "parser", Help: "hnuke mode \n\n\tparser : scan for md5/sha1/sha256 hash inside provided input file or directory\n\tanalysis : get hash of provided input file or directory and search them in VirusTotal\n"})
	recursive := parser.Flag("r", "recursive", &argparse.Options{Required: false, Help: "\nIf input path is a directory, scan for files recursively (works with both parser and analysis mode)"})
	extensions := parser.StringList("e", "extension", &argparse.Options{Required: false, Help: "If input path is a directory, include specified file extension (can be used multiple time)"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	// save file routine if program is interrupted
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		outputResults(results, *outFile, *format)
		os.Exit(1)
	}()

	switch *mode {
	case "parser":
		if r.MatchString(*inFile) {
			// parser mode - url
			hashs, err = ExtractHashFromURL(*inFile)
			if err != nil {
				log.Fatal(err)
			}
			// parser mode - files
		} else {
			var files []string
			files, err = RetrivesFilesFromUserPath(*inFile, *extensions, *recursive)
			if err != nil {
				log.Fatal(err)
			}
			for _, f := range files {
				var h []string
				h, err = ExtractHashFromFile(f)
				if err != nil {
					log.Fatal(err)
				}
				hashs = append(hashs, h...)
			}
		}

	case "analysis":
		if r.MatchString(*inFile) {
			// analysis mode - url
			var h string
			h, err = HashContentFromURL(*inFile)
			if err != nil {
				log.Fatal(err)
			}
			hashs = append(hashs, h)
		} else {
			// analysis mode - files
			files, err := RetrivesFilesFromUserPath(*inFile, *extensions, *recursive)
			if err != nil {
				log.Fatal(err)
			}

			for _, f := range files {
				var h string
				h, err = HashContentFromFile(f)
				if err != nil {
					log.Fatal(err)
				}
				hashs = append(hashs, h)
			}
		}
	default:
		log.Fatal("Unknown hnuke mode - please specify parser or analysis mode")
	}

	// hash search on VirusTotal
	hashs = UniqueSliceMembers(hashs)
	bar := progressbar.Default(int64(len(hashs)))
	for _, h := range hashs {
		res, err := GetHashInformations(h, *apikey)
		if err != nil {
			log.Fatal(err)
		}

		// check if the current result was already searched on another hashs type (avoid duplicate entries)
		if len(res.id) > 0 && !StringInSlice(res.id, buffer) {
			buffer = append(buffer, res.Sha256)
			results = append(results, res)
		}
		bar.Add(1)
	}

	outputResults(results, *outFile, *format)
}

func outputResults(results []VTResult, out string, format string) {
	var content []byte
	var buffer bytes.Buffer

	if len(results) > 0 {
		var err error
		switch strings.ToLower(format) {
		case "json":
			// json output
			content, err = json.Marshal(results)
			if err != nil {
				log.Fatal(err)
			}
		default:
			// csv output (default)
			writer := csv.NewWriter(&buffer)

			for i, value := range results {
				if i == 0 {
					if err := writer.Write(value.GetHeaders()); err != nil {
						log.Fatal(err)
					}
				}

				if err := writer.Write(value.GetValues()); err != nil {
					log.Fatal(err)
				}
			}

			writer.Flush()
			if err := writer.Error(); err != nil {
				log.Fatal(err)
			}

			content = buffer.Bytes()
		}
	}

	// save data to standard output or file
	if len(content) > 0 {
		if len(out) == 0 {
			fmt.Println(string(content))
		} else {
			var outFile string
			outFile = out
			if (strings.ToLower(format) == "json" || strings.ToLower(format) == "csv") && !strings.HasSuffix(strings.ToLower(out), strings.ToLower(format)) {
				outFile += "." + strings.ToLower(format)
			}

			f, err := os.OpenFile(outFile, os.O_RDWR|os.O_CREATE, 0755)
			if err != nil {
				log.Fatal(err)
			}

			if _, err = f.Write(content); err != nil {
				log.Fatal(err)
			}

			if err := f.Close(); err != nil {
				log.Fatal(err)
			}

		}
	}

}
