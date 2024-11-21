package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"net/http"
	"strings"
	"time"

	"github.com/mojocn/base64Captcha"
	"github.com/patrickmn/go-cache"
)

func main() {}

const pluginName = "krakend-captcha"

// HandlerRegisterer registers the plugin
var HandlerRegisterer = registerer(pluginName)

var store base64Captcha.Store

var errInternalServer = HTTPResponse{
	Code:         http.StatusInternalServerError,
	Msg:          "",
	HTTPEncoding: "application/json",
}

type EndpointKey struct {
	Path   string
	Method string
}

type RateLimiterData struct {
	RemainingBypass int
	LastRequestTime time.Time
}

var logger Logger = nil

type registerer string

func (r registerer) RegisterHandlers(f func(
	name string,
	handler func(context.Context, map[string]interface{}, http.Handler) (http.Handler, error),
)) {
	f(string(r), r.registerHandlers)
}

func (r registerer) RegisterLogger(in interface{}) {
	l, ok := in.(Logger)
	if !ok {
		return
	}

	logger = l
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Logger loaded", HandlerRegisterer))
}

func (r registerer) registerHandlers(_ context.Context, extra map[string]interface{}, h http.Handler) (http.Handler, error) {
	if logger != nil {
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] loading config", HandlerRegisterer))
	}

	config, ok := extra[pluginName].(map[string]interface{})
	if !ok {
		if logger != nil {
			logger.Error(fmt.Sprintf("[PLUGIN: %s] configuration not found", HandlerRegisterer))
		}

		return h, errors.New("configuration not found")
	}

	getCaptchaPath, ok := config["get-captcha-path"].(string)
	if !ok {
		getCaptchaPath = "/captcha"
	}

	getCaptchaMethod, ok := config["get-captcha-method"].(string)
	if !ok {
		getCaptchaMethod = "GET"
	}

	captchaLimit := 10240
	if v, ok := config["captcha-limit"]; ok {
		captchaLimit = int(v.(float64))
	}

	expiration := 10 * time.Minute
	if v, ok := config["expiration"]; ok {
		expiration = time.Duration(int(v.(float64))) * time.Second
	}

	store = base64Captcha.NewMemoryStore(captchaLimit, expiration)

	endpointsConfig, ok := config["endpoints"].([]interface{})
	if !ok {
		if logger != nil {
			logger.Error(fmt.Sprintf("[PLUGIN: %s] 'endpoints' property not found or invalid", HandlerRegisterer))
		}

		return h, errors.New("'endpoints' property not found or invalid")
	}

	endpointsMap := make(map[EndpointKey]map[string]interface{})

	for _, ep := range endpointsConfig {
		epMap, ok := ep.(map[string]interface{})
		if !ok {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] invalid endpoint format", HandlerRegisterer))
			}

			return h, errors.New("invalid endpoint format")
		}

		// Extract individual fields
		path := fmt.Sprint(epMap["path"])
		method := fmt.Sprint(epMap["method"])

		// Handle missing "bypasses" or "ttl" with default values of 0
		bypasses := 0
		if v, ok := epMap["bypasses"]; ok {
			bypasses = int(v.(float64)) // Assuming float64 if from JSON
		}

		if bypasses < 0 {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] endpoints captcha bypasses should not be less than 0", HandlerRegisterer))
			}

			return h, errors.New("endpoints captcha bypasses should not be less than 0")
		}

		ttl := 1
		if v, ok := epMap["ttl"]; ok {
			ttl = int(v.(float64)) // Assuming float64 if from JSON
		}

		if ttl < 1 {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] endpoints captcha bypass ttl should be greater than 0", HandlerRegisterer))
			}

			return h, errors.New("endpoints captcha bypass ttl should be greater than 0")
		}

		// Create an EndpointKey struct for the map key
		key := EndpointKey{
			Path:   path,
			Method: method,
		}

		// Assign the fields to the map with the EndpointKey as the key
		endpointsMap[key] = map[string]interface{}{
			"bypasses": bypasses,
			"ttl":      ttl,
		}
	}

	allowedTypes := NewStringSet()

	var audioLength int
	var driverDigit base64Captcha.DriverDigit
	var driverMath base64Captcha.DriverMath
	var driverString base64Captcha.DriverString

	getBool := func(key string, def bool) bool {
		if v, ok := config[key].(bool); ok {
			return v
		}
		return def
	}

	getIntInRange := func(key string, def, min, max int) (int, error) {
		if v, ok := config[key].(float64); ok {
			vInt := int(v)
			if vInt < min || vInt > max {
				return def, fmt.Errorf("invalid %s: %d, must be between %d and %d", key, vInt, min, max)
			}
			return vInt, nil
		}
		return def, nil
	}

	getString := func(key, def string) string {
		if v, ok := config[key].(string); ok {
			return v
		}
		return def
	}

	// Audio settings
	audio := getBool("audio", true)
	if audio {
		var err error
		audioLength, err = getIntInRange("audio-length", 6, 1, 10)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}

		allowedTypes.Add("audio")
	}

	// String settings
	stringEnabled := getBool("string", true)
	if stringEnabled {
		stringImgHeight, err := getIntInRange("string-img-height", 60, 30, 80)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}
		stringImgWidth, err := getIntInRange("string-img-width", 240, 20, 480)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}
		stringNoiseCount, err := getIntInRange("string-noise-count", 0, 0, 480)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}
		stringLength, err := getIntInRange("string-length", 6, 0, 10)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}

		stringSource := getString("string-source", "1234567890qwertyuioplkjhgfdsazxcvbnm")
		if stringSource != strings.ToLower(stringSource) {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] stirng-source should be lowercase string of all possible characters for captcha", HandlerRegisterer))
			}
			return h, err
		}

		// Set line options based on flags
		showLineOptions := 0
		if getBool("string-show-hollow-line", false) {
			showLineOptions |= base64Captcha.OptionShowHollowLine
		}
		if getBool("string-show-slime-line", false) {
			showLineOptions |= base64Captcha.OptionShowSlimeLine
		}
		if getBool("string-show-sine-line", false) {
			showLineOptions |= base64Captcha.OptionShowSineLine
		}

		// Background color
		stringBgR, _ := getIntInRange("string-bg-r", 0, 0, 255)
		stringBgG, _ := getIntInRange("string-bg-g", 0, 0, 255)
		stringBgB, _ := getIntInRange("string-bg-b", 0, 0, 255)
		stringBgA, _ := getIntInRange("string-bg-a", 0, 0, 255)
		bgColor := &color.RGBA{R: uint8(stringBgR), G: uint8(stringBgG), B: uint8(stringBgB), A: uint8(stringBgA)}

		driverString = base64Captcha.DriverString{
			Height:          stringImgHeight,
			Width:           stringImgWidth,
			NoiseCount:      stringNoiseCount,
			ShowLineOptions: showLineOptions,
			Length:          stringLength,
			Source:          stringSource,
			BgColor:         bgColor,
		}

		allowedTypes.Add("string")
	}

	mathEnabled := getBool("math", true)
	if mathEnabled {
		mathImgHeight, err := getIntInRange("math-img-heigth", 60, 30, 80)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}
		mathImgWidth, err := getIntInRange("math-img-width", 240, 20, 480)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}
		mathNoiseCount, err := getIntInRange("math-noise-count", 0, 0, 480)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}

		// Set line options for math
		mathShowLineOptions := 0
		if getBool("math-show-hollow-line", false) {
			mathShowLineOptions |= base64Captcha.OptionShowHollowLine
		}
		if getBool("math-show-slime-line", false) {
			mathShowLineOptions |= base64Captcha.OptionShowSlimeLine
		}
		if getBool("math-show-sine-line", false) {
			mathShowLineOptions |= base64Captcha.OptionShowSineLine
		}

		// Background color for math
		mathBgR, _ := getIntInRange("math-bg-r", 0, 0, 255)
		mathBgG, _ := getIntInRange("math-bg-g", 0, 0, 255)
		mathBgB, _ := getIntInRange("math-bg-b", 0, 0, 255)
		mathBgA, _ := getIntInRange("math-bg-a", 0, 0, 255)
		bgColor := &color.RGBA{R: uint8(mathBgR), G: uint8(mathBgG), B: uint8(mathBgB), A: uint8(mathBgA)}

		driverMath = base64Captcha.DriverMath{
			Height:          mathImgHeight,
			Width:           mathImgWidth,
			NoiseCount:      mathNoiseCount,
			ShowLineOptions: mathShowLineOptions,
			BgColor:         bgColor,
		}

		allowedTypes.Add("math")
	}

	// Digit settings
	digitEnabled := getBool("digit", true)
	if digitEnabled {
		digitImgHeight, err := getIntInRange("digit-img-heigth", 80, 30, 180)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}
		digitImgWidth, err := getIntInRange("digit-img-width", 240, 20, 480)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}
		digitLength, err := getIntInRange("digit-length", 6, 1, 10)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}
		digitMaxSkew := 0.7
		if v, ok := config["digit-max-skew"].(float64); ok && v >= 0.1 && v <= 1.0 {
			digitMaxSkew = v
		} else if ok {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] Invalid digit-max-skew: %v", HandlerRegisterer, v))
			}
			return h, err
		}
		digitDotCount, err := getIntInRange("digit-dot-count", 80, 2, 100)
		if err != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("[PLUGIN: %s] %v", HandlerRegisterer, err))
			}
			return h, err
		}

		driverDigit = base64Captcha.DriverDigit{
			Height:   digitImgHeight,
			Width:    digitImgWidth,
			Length:   digitLength,
			MaxSkew:  digitMaxSkew,
			DotCount: digitDotCount,
		}

		allowedTypes.Add("digit")
	}

	if allowedTypes.Size() == 0 {
		if logger != nil {
			logger.Error(fmt.Sprintf("[PLUGIN: %s] You should specify in config at least one captcha type", HandlerRegisterer))
		}
		return h, errors.New("you should specify in config at least one captcha type")
	}

	// Use a go-cache instance for automatic expiration and cleanup
	userRateLimitCache := cache.New(5*time.Minute, 10*time.Minute)

	if logger != nil {
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] config successfully loaded", HandlerRegisterer))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		userIp := req.RemoteAddr
		reqPath := req.URL.Path
		reqMethod := req.Method

		// Check if the request path and method match the captcha endpoint
		if reqPath == getCaptchaPath && reqMethod == getCaptchaMethod {
			query := req.URL.Query()

			captchaPath := query.Get("path")
			if captchaPath == "" {
				httpError := getError("INVALID_CAPTCHA_PATH", "To generate captcha 'path' required in query params", http.StatusBadRequest)
				writeErrorResponse(w, httpError)
				return
			}

			captchaMethod := query.Get("method")
			if captchaMethod == "" {
				httpError := getError("INVALID_CAPTCHA_METHOD", "To generate captcha 'method' required in query params", http.StatusBadRequest)
				writeErrorResponse(w, httpError)
				return
			}

			key := EndpointKey{Path: captchaPath, Method: captchaMethod}
			val, exists := endpointsMap[key]
			if !exists {
				httpError := getError("CAPTCHA_NOT_REQUIRED", "Captcha not required for the selected endpoint path and method", http.StatusBadRequest)
				writeErrorResponse(w, httpError)
				return
			}

			captchaType := query.Get("type")

			// Determine the captcha type
			if captchaType == "" {
				if allowedTypes.Contains("string") {
					captchaType = "string"
				} else if allowedTypes.Contains("digit") {
					captchaType = "digit"
				} else if allowedTypes.Contains("math") {
					captchaType = "math"
				} else {
					captchaType = "audio"
				}
			} else if !allowedTypes.Contains(captchaType) {
				httpError := getError("INVALID_CAPTCHA_TYPE", "Invalid captcha type", http.StatusBadRequest)
				writeErrorResponse(w, httpError)
				return
			}

			audioLang := query.Get("lang")
			if audioLang != "" {
				if !allowedTypes.Contains("audio") {
					httpError := getError("CAPTCHA_LANG_NOT_SUPPORTED", "Audio captchas are disabled", http.StatusBadRequest)
					writeErrorResponse(w, httpError)
					return
				}

				if captchaType != "audio" {
					httpError := getError("CAPTCHA_LANG_NOT_SUPPORTED_FOR_METHOD", "Query param 'lang' only supported with audio captcha type", http.StatusBadRequest)
					writeErrorResponse(w, httpError)
					return
				}

				if audioLang != "en" && audioLang != "ja" && audioLang != "ru" && audioLang != "zh" {
					httpError := getError("CAPTCHA_LANG_INVALID", "Invalid captcha lang. Supported values: en, ja, ru, zh", http.StatusBadRequest)
					writeErrorResponse(w, httpError)
					return
				}
			} else if captchaType == "audio" {
				audioLang = "en"
			}

			bypasses := val["bypasses"].(int)
			if bypasses > 0 {
				cacheKey := userIp + captchaPath + captchaMethod
				rateDataInterface, found := userRateLimitCache.Get(cacheKey)

				if !found {
					w.WriteHeader(http.StatusNoContent)
					return
				}

				// Load the rate limiter data from cache
				rateData := rateDataInterface.(*RateLimiterData)

				// If captcha is not required, send 204 No Content response
				if rateData.RemainingBypass > 0 {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}

			var driver base64Captcha.Driver

			// Determine the captcha driver based on type
			switch captchaType {
			case "audio":
				driver = &base64Captcha.DriverAudio{
					Length:   audioLength,
					Language: audioLang,
				}
			case "string":
				driver = &driverString
			case "math":
				driver = &driverMath
			case "digit":
				driver = &driverDigit
			}

			// Generate the captcha
			c := base64Captcha.NewCaptcha(driver, store)
			id, content, answer := c.Driver.GenerateIdQuestionAnswer()
			item, err := c.Driver.DrawCaptcha(content)

			if err != nil {
				if logger != nil {
					logger.Error(fmt.Sprintf("[PLUGIN: %s] Generate captcha error: %s", HandlerRegisterer, err.Error()))
				}

				httpError := getError("CAPTCHA_GENERATE_ERROR", "Error generating captcha", http.StatusInternalServerError)
				writeErrorResponse(w, httpError)
				return
			}

			combined := userIp + captchaPath + captchaMethod
			hash := shortHash(combined)
			storeKey := hash + id

			c.Store.Set(storeKey, answer)

			responseData := map[string]string{
				"id":   id,
				"data": item.EncodeB64string(),
			}

			jsonData, err := json.Marshal(responseData)
			if err != nil {
				if logger != nil {
					logger.Error(fmt.Sprintf("[PLUGIN: %s] JSON marshal error: %s", HandlerRegisterer, err.Error()))
				}

				httpError := getError("JSON_MARSHAL_ERROR", "Error marshaling JSON", http.StatusInternalServerError)
				writeErrorResponse(w, httpError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(jsonData)
			return
		}

		key := EndpointKey{Path: reqPath, Method: reqMethod}
		val, exists := endpointsMap[key]
		if !exists {
			h.ServeHTTP(w, req)
			return
		}

		headers := req.Header
		captchaId := getHeader(headers, "X-Captcha-Id")
		captchaValue := getHeader(headers, "X-Captcha-Value")
		cacheKey := userIp + reqPath + reqMethod

		if captchaId == "" && captchaValue == "" {
			bypasses := val["bypasses"].(int)
			if bypasses > 0 {
				rateDataInterface, found := userRateLimitCache.Get(cacheKey)
				var rateData *RateLimiterData

				ttl := time.Duration(val["ttl"].(int)) * time.Second

				if !found {
					// No data found, initialize a new entry
					rateData = &RateLimiterData{
						RemainingBypass: bypasses,
						LastRequestTime: time.Now(),
					}
					// Store the new rate limiter data in the cache with TTL
					userRateLimitCache.Set(cacheKey, rateData, ttl)

					if logger != nil {
						logger.Debug(fmt.Sprintf("[PLUGIN: %s] Bypass entry is initialized for a new user", HandlerRegisterer))
					}
				} else {
					// Load the rate limiter data from cache
					rateData = rateDataInterface.(*RateLimiterData)
				}

				if rateData.RemainingBypass > 0 {
					// Allow bypass, decrement remaining bypasses
					rateData.RemainingBypass--

					// Update the rate limiter data back into the cache
					userRateLimitCache.Set(cacheKey, rateData, ttl)

					if logger != nil {
						logger.Debug(fmt.Sprintf("[PLUGIN: %s] Bypass allowed", HandlerRegisterer))
					}

					// Process the request
					h.ServeHTTP(w, req)
					return
				}
			}
		}

		// Captcha is required or no bypasses are left

		// Check X-Captcha-Id header
		if captchaId == "" {
			if logger != nil {
				logger.Debug(fmt.Sprintf("[PLUGIN: %s] Request rejected: X-Captcha-Id header is missing", HandlerRegisterer))
			}

			httpError := getError("CAPTCHA_REQUIRED", "Captcha is required", http.StatusBadRequest)
			writeErrorResponse(w, httpError)
			return
		}

		// Check X-Captcha-Value header
		if captchaValue == "" {
			if logger != nil {
				logger.Debug(fmt.Sprintf("[PLUGIN: %s] Request rejected: X-Captcha-Value header is missing", HandlerRegisterer))
			}

			httpError := getError("CAPTCHA_REQUIRED", "Captcha is required", http.StatusBadRequest)
			writeErrorResponse(w, httpError)
			return
		}

		hash := shortHash(cacheKey)
		storeKey := hash + captchaId

		if !store.Verify(storeKey, strings.ToLower(captchaValue), true) {
			if logger != nil {
				logger.Debug(fmt.Sprintf("[PLUGIN: %s] Request rejected: invalid or expired captcha", HandlerRegisterer))
			}

			httpError := getError("CAPTCHA_INVALID_OR_EXPIRED", "Captcha is invalid or expired", http.StatusForbidden)
			writeErrorResponse(w, httpError)
			return
		}

		// If validation succeeds, continue with the request
		h.ServeHTTP(w, req)
	}), nil
}

func getError(errorType, message string, statusCode int) HTTPResponse {
	// Generate current timestamp
	timestamp := time.Now().Format(time.RFC3339)

	// Create the JSON response
	content := map[string]interface{}{
		"statusCode": statusCode,
		"timestamp":  timestamp,
		"type":       errorType,
		"error":      message,
	}

	// Marshal the content to JSON
	jsonContent, err := json.Marshal(content)
	if err != nil {
		return errInternalServer
	}

	return HTTPResponse{
		Code:         statusCode,
		Msg:          string(jsonContent),
		HTTPEncoding: "application/json",
	}
}

// Helper function to write the error response
func writeErrorResponse(w http.ResponseWriter, httpError HTTPResponse) {
	w.Header().Set("Content-Type", httpError.HTTPEncoding)
	w.WriteHeader(httpError.Code)
	w.Write([]byte(httpError.Msg))
}

// Helper function to get a specific header from the request
func getHeader(headers map[string][]string, key string) string {
	if values, ok := headers[key]; ok && len(values) > 0 {
		return values[0]
	}

	return ""
}

// Get short hash from string
func shortHash(value string) string {
	// Compute MD5 hash of the string
	hash := md5.Sum([]byte(value))

	// Convert the hash to a hexadecimal string
	hashString := fmt.Sprintf("%x", hash)

	// Return the first 6 characters
	return hashString[:6]
}

// Logger interface for logging
type Logger interface {
	Debug(v ...interface{})
	Info(v ...interface{})
	Warning(v ...interface{})
	Error(v ...interface{})
	Critical(v ...interface{})
	Fatal(v ...interface{})
}

type HTTPResponse struct {
	Code         int    `json:"http_status_code"`
	Msg          string `json:"http_body,omitempty"`
	HTTPEncoding string `json:"http_encoding"`
}

// Error returns the error message
func (r HTTPResponse) Error() string {
	return r.Msg
}

// StatusCode returns the status code returned by the backend
func (r HTTPResponse) StatusCode() int {
	return r.Code
}

// Encoding returns the HTTP output encoding
func (r HTTPResponse) Encoding() string {
	return r.HTTPEncoding
}

// StringSet is a set of strings.
type StringSet struct {
	elements map[string]struct{}
}

// NewStringSet creates a new StringSet.
func NewStringSet() *StringSet {
	return &StringSet{elements: make(map[string]struct{})}
}

// Add adds a string to the set.
func (s *StringSet) Add(value string) {
	s.elements[value] = struct{}{}
}

// Contains checks if a string is in the set.
func (s *StringSet) Contains(value string) bool {
	_, exists := s.elements[value]
	return exists
}

// Size returns the number of elements in the set.
func (s *StringSet) Size() int {
	return len(s.elements)
}
