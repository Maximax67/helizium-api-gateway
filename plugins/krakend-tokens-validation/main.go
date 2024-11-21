package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func main() {}

const pluginName = "krakend-tokens-validation"

// ModifierRegisterer registers the plugin
var ModifierRegisterer = registerer(pluginName)

var errUnauthorized = HTTPResponseError{
	Code:         http.StatusUnauthorized,
	Msg:          "",
	HTTPEncoding: "application/json",
}

var logger Logger = nil

type registerer string

var serverStartupTime int64

func (r registerer) RegisterModifiers(f func(
	name string,
	modifierFactory func(map[string]interface{}) func(interface{}) (interface{}, error),
	appliesToRequest bool,
	appliesToResponse bool,
)) {
	serverStartupTime = time.Now().Unix()
	f(string(r), r.modifierFactory, true, false)
}

func (r registerer) RegisterLogger(in interface{}) {
	l, ok := in.(Logger)
	if !ok {
		return
	}

	logger = l
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Logger loaded", ModifierRegisterer))
}

func (r registerer) modifierFactory(extra map[string]interface{}) func(interface{}) (interface{}, error) {
	if logger != nil {
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] loading config", ModifierRegisterer))
	}

	config, ok := extra[pluginName].(map[string]interface{})
	if !ok {
		if logger != nil {
			logger.Error(fmt.Sprintf("[PLUGIN: %s] configuration not found", ModifierRegisterer))
		}

		return nil
	}

	validatorUrl, ok := config["api-tokens-validator-url"].(string)
	if !ok {
		if logger != nil {
			logger.Error(fmt.Sprintf("[PLUGIN: %s] api-tokens-validator-url not provided in config", ModifierRegisterer))
		}

		return nil
	}

	verifyApiTokens, ok := config["verify-api-tokens"].(bool)
	if !ok {
		if logger != nil {
			logger.Error(fmt.Sprintf("[PLUGIN: %s] verify-api-tokens not provided in config", ModifierRegisterer))
		}

		return nil
	}

	if logger != nil {
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] config successfully loaded", ModifierRegisterer))
	}

	return func(input interface{}) (interface{}, error) {
		req, ok := input.(RequestWrapper)
		if !ok {
			return nil, errors.New("unknown request type")
		}

		headers := req.Headers()

		// Extract X-Token-Iat header
		tokenIat := getHeader(headers, "X-Token-Iat")
		if tokenIat == "" {
			if logger != nil {
				logger.Debug(fmt.Sprintf("[PLUGIN: %s] Token rejected: iat is missing", ModifierRegisterer))
			}

			return nil, errUnauthorized
		}

		// Convert X-Token-Iat to Unix timestamp and compare it with server startup time
		tokenIatTime, err := strconv.ParseInt(tokenIat, 10, 64)
		if err != nil {
			if logger != nil {
				logger.Debug(fmt.Sprintf("[PLUGIN: %s] Token rejected: invalid iat", ModifierRegisterer))
			}

			return nil, errUnauthorized
		}

		// Extract X-Token-Jti header
		tokenJti := getHeader(headers, "X-Token-Jti")
		if tokenJti == "" {
			if logger != nil {
				logger.Debug(fmt.Sprintf("[PLUGIN: %s] Token rejected: jti is missing", ModifierRegisterer))
			}

			return nil, errUnauthorized
		}

		// Check for X-Token-Type header
		tokenType := getHeader(headers, "X-Token-Type")
		if tokenType != "API" && tokenType != "" {
			// Reject ACCESS tokens issued before server startup time
			if tokenType == "ACCESS" && tokenIatTime < serverStartupTime {
				if logger != nil {
					logger.Debug(fmt.Sprintf("[PLUGIN: %s] Token rejected: issued before server startup", ModifierRegisterer))
				}

				return nil, errUnauthorized
			}

			tokenExp := getHeader(headers, "X-Token-Exp")
			if tokenExp == "" {
				if logger != nil {
					logger.Debug(fmt.Sprintf("[PLUGIN: %s] Token rejected: expiration date is missing", ModifierRegisterer))
				}

				return nil, errUnauthorized
			}

			return req, nil
		}

		if !verifyApiTokens {
			return req, nil
		}

		// Validate the API token JTI by sending it to the auth server
		if err := validateTokenJti(validatorUrl, tokenJti); err != nil {
			return nil, err
		}

		// If validation succeeds, continue with the request
		return req, nil
	}
}

// Helper function to get a specific header from the request
func getHeader(headers map[string][]string, key string) string {
	if values, ok := headers[key]; ok && len(values) > 0 {
		return values[0]
	}

	return ""
}

// Helper function to validate the token JTI with the auth server via POST
func validateTokenJti(validatorUrl, tokenJti string) error {
	// Create the JSON payload with the JTI
	jsonBody := fmt.Sprintf(`{"jti": "%s"}`, tokenJti)
	bodyReader := strings.NewReader(jsonBody)

	// Create a new HTTP POST request
	req, err := http.NewRequest("POST", validatorUrl, bodyReader)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	// Initialize the HTTP client and send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// If the auth server returns 200, the token is valid
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	// If the status is 403, return a custom error with the body message
	if resp.StatusCode == http.StatusForbidden {
		// Read the response body
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		bodyString := string(bodyBytes)

		return HTTPResponseError{
			Code:         http.StatusForbidden,
			Msg:          bodyString,
			HTTPEncoding: "application/json",
		}
	}

	// Any other responses
	return errUnauthorized
}

// RequestWrapper interface to work with requests
type RequestWrapper interface {
	Params() map[string]string
	Headers() map[string][]string
	Body() io.ReadCloser
	Method() string
	URL() *url.URL
	Query() url.Values
	Path() string
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

type HTTPResponseError struct {
	Code         int    `json:"http_status_code"`
	Msg          string `json:"http_body,omitempty"`
	HTTPEncoding string `json:"http_encoding"`
}

// Error returns the error message
func (r HTTPResponseError) Error() string {
	return r.Msg
}

// StatusCode returns the status code returned by the backend
func (r HTTPResponseError) StatusCode() int {
	return r.Code
}

// Encoding returns the HTTP output encoding
func (r HTTPResponseError) Encoding() string {
	return r.HTTPEncoding
}
