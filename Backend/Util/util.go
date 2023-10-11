package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"unicode"

	config "messenger/Config"
	"regexp"

	"github.com/go-email-validator/go-email-validator/pkg/ev"
	"github.com/go-email-validator/go-email-validator/pkg/ev/evmail"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

var conf = config.GetConfig("config.yaml")

type API struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

const date_layout = "2006-01-02"
const date_time_layout = "2006-01-02 15:04:05"

func Hash_sha256(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	//log.Println(password)
	//fmt.Printf("%x\n", bs)
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func Contains(arr []string, target string) bool {
	for _, element := range arr {
		if element == target {
			return true
		}
	}
	return false
}

func ContainsInt(arr []int, target int) bool {
	for _, element := range arr {
		if element == target {
			return true
		}
	}
	return false
}

func GenerateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func Generate6DigitsCode() string {
	b := make([]byte, 3)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// func CheckValidToken(token string, redisClient *redis.Client) bool {
// 	_, err := redisClient.Get(token).Result()
// 	return err == nil
// }

func DownloadImage(url string, fileName string) error {
	resp, err := http.Get(url)
	if err != nil {
		log.Println(err)
		log.Println("Error while http get: ", err)
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		log.Println("Error while read body: ", err)
		return err
	}
	err = os.WriteFile(fileName, body, 0644)
	if err != nil {
		log.Println(err)
		log.Println("Error while write file: ", err)
		return err
	}
	return nil
}

func ReadFileAndReturnBase64(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		log.Println(err)
		return "", err
	}
	defer file.Close()

	fileStat, err := file.Stat()
	if err != nil {
		log.Println(err)
		return "", err
	}

	fileSize := fileStat.Size()
	fileContent := make([]byte, fileSize)

	_, err = file.Read(fileContent)
	if err != nil {
		log.Println(err)
		return "", err
	}

	// Encode the binary data to base64
	encoded := base64.StdEncoding.EncodeToString(fileContent)
	return encoded, nil
}

func DecodeBase64AndWriteFile(encoded string, outputFilename string) error {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Println(err)
		return err
	}

	file, err := os.Create(outputFilename)
	if err != nil {
		log.Println(err)
		return err
	}
	defer file.Close()

	_, err = file.Write(decoded)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func JsonToString(m map[string]interface{}) (string, error) {
	j, err := json.Marshal(m)
	if err != nil {
		log.Println(err)
		log.Println("error:", err)
		return "", err
	}

	// print the JSON string
	return string(j), err
}

func StringToAnyJSON(str string) (map[string]any, error) {
	//log.Println("Parsing string to JSON:\n", str)
	//str = SelfStringEscape(str)
	var result map[string]any
	error := json.Unmarshal([]byte(str), &result)
	if error != nil {
		log.Println("ERROR PARSING JSON: ", error)
		return nil, error
	}
	return result, nil
}

func StringIfNotEmptyToAnyArray(str string) ([]map[string]any, error) {
	var data []map[string]interface{}
	if str == "" {
		return data, nil
	}

	// Unmarshal the JSON string into the list of map interfaces
	err := json.Unmarshal([]byte(str), &data)
	if err != nil {
		fmt.Println("Error parsing JSON to array:", err)
		return nil, err
	}
	return data, nil
}

func StringIfNotEmptyToIntArray(str string) ([]int, error) {
	var data []int
	if str == "" {
		return data, nil
	}
	// Unmarshal the JSON data (array of integers) into the slice
	err := json.Unmarshal([]byte(str), &data)
	if err != nil {
		fmt.Println("Error parsing JSON to int array", err)
		return nil, err
	}

	return data, nil
}

func StringIfNotEmptyToStringArray(str string) ([]string, error) {
	var data []string
	if str == "" {
		return data, nil
	}
	// Unmarshal the JSON data (array of integers) into the slice
	err := json.Unmarshal([]byte(str), &data)
	if err != nil {
		fmt.Println("Error parsing JSON to string array", err)
		return nil, err
	}

	return data, nil
}

func HandleImageRelatedFields(bodyStruct *map[string]interface{}, fields []string, fileName string) error {
	for _, field := range fields {
		if _, ok := (*bodyStruct)[field]; !ok {
			log.Println("Field " + field + " is empty")
			return errors.New("Field " + field + " is empty")
		}
		err := DecodeBase64AndWriteFile((*bodyStruct)[field].(string), "../Data/"+fileName+"_"+field)
		if err != nil {
			log.Println(err)
			log.Println("Cannot write file of " + field)
			return errors.New("Cannot write file of " + field)
		}
		(*bodyStruct)[field] = fileName + "_" + field
	}
	return nil
}

func GetRandomString(len int) string {
	b := make([]byte, len)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func HandleNotFound(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func IsInMapValueArrays(m map[string][]string, s string) bool {
	for _, values := range m {
		for _, value := range values {
			if s == value {
				return true
			}
		}
	}
	return false
}

func HandleWrongMethod(w http.ResponseWriter) {
	http.Error(w, "Wrong method", http.StatusMethodNotAllowed)
}

func ConvertToFloat64(strVal string) (float64, error) {
	floatVal, err := strconv.ParseFloat(strVal, 64)
	if err != nil {
		return 0, err
	}

	return floatVal, nil
}

func UnmarshalJSON(body []byte) (*API, error) {
	var data API
	err := json.Unmarshal(body, &data)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return &data, nil
}

func SelfStringEscape(str string) string {
	res := strings.Replace(str, `\/`, `/`, -1)
	//log.Println(res)
	//res = strings.Replace(str, `\`, `\\`, -1)
	res = strings.Replace(res, `/`, `\/`, -1)
	//log.Println(res)
	return res
}

func StringToJSON(str string) (map[string]interface{}, error) {
	// log.Println("Parsing string to JSON:\n", str)
	//str = SelfStringEscape(str)
	if str == "" {
		return nil, nil
	}
	var result map[string]interface{}
	err := json.Unmarshal([]byte(str), &result)
	if err != nil {
		log.Println("FAILED TO PARSE JSON WITH STRING: ", str)
		log.Println("ERROR: ", err)
		return nil, err
	}
	return result, nil
}

func RequestToStruct(req *http.Request) (map[string]interface{}, error) {
	if req.Body == nil {
		log.Println("[+] BODY IS NIL")
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Println("[+] ERR READING BODY: ", err)
		return nil, err
	}
	bodyJson, err := StringToJSON(string(body))
	return bodyJson, err
}

func GenerateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func IsValidImagesField(images []interface{}) bool {
	if len(images) < 1 || len(images) > 5 {
		return false
	}
	for _, image := range images {
		_, err := base64.StdEncoding.DecodeString(image.(string))
		if err != nil {
			return false
		}
	}
	return true
}

func TitleStr(str string) string {
	return strings.ToUpper(string(str[0])) + strings.ToLower(str[1:])
}

const (
	earthRadius = 6371 // Earth's radius in kilometers
)

type Coordinates struct {
	Latitude  float64
	Longitude float64
}

func DegreesToRadians(degrees float64) float64 {
	return degrees * math.Pi / 180
}

func CalculateDistance(src_long float64, src_lat float64, dst_long float64, dst_lat float64) float64 {
	point1 := Coordinates{Latitude: src_lat, Longitude: src_long} // Berlin, Germany
	point2 := Coordinates{Latitude: dst_lat, Longitude: dst_long} // Paris, France

	lat1 := DegreesToRadians(point1.Latitude)
	lat2 := DegreesToRadians(point2.Latitude)
	long1 := DegreesToRadians(point1.Longitude)
	long2 := DegreesToRadians(point2.Longitude)

	// Calculate the differences between the latitudes and longitudes
	dLat := lat2 - lat1
	dLon := long2 - long1

	// Apply the Haversine formula
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1)*math.Cos(lat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	distance := earthRadius * c

	// round to 2 decimal places
	distance = math.Round(distance*100) / 100

	return distance
}

func LowercaseAndUnaccent(str string) (string, error) {
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	result, _, err := transform.String(t, str)
	if err != nil {
		return "", err
	}
	return result, nil
}

func CheckEmailValid(w http.ResponseWriter, email string) bool {
	v := ev.NewSyntaxValidator().Validate(ev.NewInput(evmail.FromString(email)))
	pattern := `^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$`
	regex := regexp.MustCompile(pattern)
	if !regex.MatchString(email) || !v.IsValid() {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Invalid email",
			"exit_code": conf.GetInt("exit_code.invalid_field"),
		})
		return false
	}
	return true
}

func CheckEmailValidIfNotEmpty(w http.ResponseWriter, email string) bool {
	if email == "" {
		return true
	}
	return CheckEmailValid(w, email)
}

func CheckDateValid(w http.ResponseWriter, date string) bool {
	_, err := time.Parse(date_layout, date)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Date must be in format yyyy-MM-dd",
			"exit_code": conf.GetInt("exit_code.invalid_field"),
		})
		return false
	}
	return true
}

func CheckDateValidIfNotEmpty(w http.ResponseWriter, date string) bool {
	if date == "" {
		return true
	}
	return CheckDateValid(w, date)
}

func CheckDateTimeValidIfNotEmpty(w http.ResponseWriter, date_time string) bool {
	if date_time == "" {
		return true
	}

	_, err := time.Parse(date_time_layout, date_time)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Date time must be in format yyyy-MM-dd HH:mm:ss",
			"exit_code": conf.GetInt("exit_code.invalid_field"),
		})
		return false
	}
	return true
}

func IsValidAvailableDates(start_date string, end_date string) (bool, error) {
	time1, err := time.Parse(date_layout, start_date)
	if err != nil {
		return false, err
	}

	time2, err := time.Parse(date_layout, end_date)
	if err != nil {
		return false, err
	}

	time1_year := time1.Year()
	time2_year := time2.Year()
	if time2_year > time1_year {
		return true, nil
	}
	if time2_year < time1_year {
		return false, nil
	}
	time1_month := time1.Month()
	time2_month := time2.Month()
	if time2_month > time1_month {
		return true, nil
	}
	if time2_month < time1_month {
		return false, nil
	}
	time1_day := time1.Day()
	time2_day := time2.Day()
	if time2_day <= time1_day {
		return false, nil
	}
	return true, nil
}

func CheckTimeValid(w http.ResponseWriter, check_time string) bool {
	_, err := time.Parse("15:04", check_time)
	if err != nil {
		_, err = time.Parse("15:04:00", check_time)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message":   "Time must be in format HH:MM or HH:MM:SS",
				"exit_code": conf.GetInt("exit_code.invalid_field"),
			})
			return false
		}
	}
	return true
}

func CheckSorts(w http.ResponseWriter, sorts []map[string]any, valid_sort_fields []string, valid_sort_by []string) bool {
	for _, sort := range sorts {
		if !Contains(valid_sort_fields, sort["field"].(string)) || !Contains(valid_sort_by, sort["by"].(string)) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message":   "Invalid sort field or sort by",
				"exit_code": conf.GetInt("exit_code.invalid_field"),
			})
			return false
		}
	}
	return true
}
