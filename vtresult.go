package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
)

// VTResult includes all the relevants data which should be serialized in json and csv
type VTResult struct {
	id                 string
	rawCreationDate    int64
	rawFirstSubmission int64
	rawLastAnalysis    int64
	rawFilesize        int64

	Md5             string   `json:"md5"`
	Sha1            string   `json:"sha1"`
	Sha256          string   `json:"sha256"`
	VHash           string   `json:"vhash"`
	CreationDate    string   `json:"creation_date"`
	FirstSubmission string   `json:"first_submission"`
	LastAnalysis    string   `json:"last_analysis"`
	Filename        []string `json:"file_names"`
	FileType        string   `json:"file_type"`
	FileSize        string   `json:"file_size"`
	ImpHash         string   `json:"imphash"`
	Statement       string   `json:"statement"`
	MSDefender      string   `json:"microsoft_defender"`
	Tags            []string `json:"tags"`
	URL             string   `json:"url"`
}

// GetHeaders return the VTResult struct keys in order to serialized them into a csv content
func (f *VTResult) GetHeaders() []string {
	val := reflect.ValueOf(f).Elem()
	var headers []string

	for i := 0; i < val.NumField(); i++ {
		tag := val.Type().Field(i).Tag
		if len(tag) > 0 {
			headers = append(headers, tag.Get("json"))
		}
	}

	return headers
}

// GetValues return the VTResult struct values in order to serialized them into a csv content
func (f *VTResult) GetValues() []string {
	val := reflect.ValueOf(f).Elem()
	var values []string

	for i := 0; i < val.NumField(); i++ {
		if len(val.Type().Field(i).Tag) > 0 {
			values = append(values, fmt.Sprintf("%v", val.Field(i).Interface()))
		}
	}

	return values
}

// OutCSVFile write an array of VTResult inside a csv file
func OutCSVFile(f *os.File, results []VTResult) error {
	if len(results) == 0 {
		return errors.New("VTResult should contains at least 1 item")
	}

	writer := csv.NewWriter(f)
	if err := writer.Write(results[0].GetHeaders()); err != nil {
		return err
	}

	for _, obj := range results {
		if err := writer.Write(obj.GetValues()); err != nil {
			return err
		}
	}

	defer writer.Flush()

	return nil
}

// OutJSONFile write an array of VTResult inside a json file
func OutJSONFile(f *os.File, results []VTResult) error {
	if len(results) == 0 {
		return errors.New("VTResult should contains at least 1 item")
	}

	b, err := json.Marshal(results)

	if err != nil {
		return err
	}

	_, err = f.WriteString(string(b))

	if err != nil {
		return err
	}
	return nil
}
