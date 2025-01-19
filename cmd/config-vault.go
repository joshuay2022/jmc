// Copyright (c) 2025 Joshua.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/eiannone/keyboard"
	"github.com/minio/mc/pkg/probe"
)

const (
	jmcUsernameEnv = "JMC_VAULT_USERNAME"
	jmcPasswordEnv = "JMC_VAULT_PASSWORD"

	jmcAliasNameVKey = "alias"
	jmcAddressVKey   = "url"
	jmcKeyVKey       = "key"
	jmcSecretVKey    = "secret"
	jmcAPIVKey       = "api"
	jmcPathVKey      = "path"

	jmcAPIDefault  = "s3v4"
	jmcPathDefault = "auto"
)

var (
	jmcVaultAddress string // jmc: vault address assigned in compilation
	jmcSecretEngine string // jmc: secret engine assigned in compilation
	jmcSecretsPaths string // jmc: secret paths assigned in compilation
)

// PostJSON makes a POST request to the given URL with the provided payload
// and returns the JSON response as a map and an error (nil if no error).
func httpPOSTJSON(url string, payload map[string]interface{}) (map[string]interface{}, error) {
	// Convert the payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshalling JSON: %w", err)
	}

	// Create a custom HTTP client that skips certificate verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Create the POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Response code: %d. Error reading response body: %w", statusCode, err)
	}

	// Parse the JSON response
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("Response code: %d. Error parsing JSON response: %w", statusCode, err)
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("Response code: %d\nError information:\n%s", statusCode, string(body))
	}

	// Return the parsed JSON response and nil error
	return jsonResponse, nil
}

func getUserToken(vaultAddr string, username string, password string) (string, error) {
	// Create the JSON payload
	payload := map[string]interface{}{
		"password": password,
	}

	url := vaultAddr + "/v1/auth/userpass/login/" + username

	jsonResponse, err := httpPOSTJSON(url, payload)
	if err != nil {
		return "", err
	}

	if auth, ok := jsonResponse["auth"]; ok {
		if authJson, ok := auth.(map[string]interface{}); ok {
			if clientToken, ok := authJson["client_token"]; ok {
				if clientTokenStr, ok := clientToken.(string); ok {
					return clientTokenStr, nil
				}
			}
		}
	}

	return "", fmt.Errorf("Not found a valid client token from response JSON")
}

// sendGETRequest sends a GET request to the specified URL with the
// X-Vault-Token header and returns the parsed JSON response
func httpGETRequest(url, token string) (map[string]interface{}, error) {
	// Create a custom HTTP client that skips certificate verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip cert verification
		},
	}

	// Create the GET request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set the X-Vault-Token header
	req.Header.Set("X-Vault-Token", token)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Response code: %d. Error reading response body: %w", statusCode, err)
	}

	// Parse the JSON response
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("Response code: %d. Error parsing JSON response: %w", statusCode, err)
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("Response code: %d\nError information:\n%s", statusCode, string(body))
	}

	// Return the parsed JSON response and nil error
	return jsonResponse, nil
}

func getUserSecrets(vaultAddr string, secretEngine string, pathPre string, token string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/v1/%s/data/%s", vaultAddr, secretEngine, pathPre)

	jsonResponse, err := httpGETRequest(url, token)
	if err != nil {
		return nil, err
	}

	if data1, ok := jsonResponse["data"]; ok {
		if data1Json, ok := data1.(map[string]interface{}); ok {
			if data2, ok := data1Json["data"]; ok {
				if data2Json, ok := data2.(map[string]interface{}); ok {
					return data2Json, nil
				} else {
					return nil, fmt.Errorf("'.data.data' from response JSON is not valid key-secret")
				}
			} else {
				return nil, fmt.Errorf("Not found '.data.data' from response JSON")
			}
		}
	} else {
		return nil, fmt.Errorf("Not found '.data' from response JSON")
	}

	return nil, fmt.Errorf("Not found valid secret data from response JSON")
}

func getUsernamePassword() (string, string, *probe.Error) {
	username := os.Getenv(jmcUsernameEnv)
	password := os.Getenv(jmcPasswordEnv)
	fmt.Println("Not found username and password in env.")
	if len(username) == 0 || len(password) == 0 {
		fmt.Print("Please enter your username: ")
		fmt.Scan(&username)

		fmt.Print("Please enter your password: ")

		// Initialize the keyboard package
		if err := keyboard.Open(); err != nil {
			return "", "", probe.NewError(err)
		}
		defer keyboard.Close()

		for {
			// Read a single keypress
			char, key, err := keyboard.GetKey()
			if err != nil {
				return "", "", probe.NewError(err)
			}

			// Handle Enter key (finish input)
			if key == keyboard.KeyEnter {
				fmt.Println()
				break
			}

			// Handle Backspace (delete last character)
			if (key == keyboard.KeyBackspace || key == keyboard.KeyBackspace2) && len(password) > 0 {
				password = password[:len(password)-1]
				fmt.Print("\b \b") // Move cursor back, erase character, and move back again
				continue
			}

			// Append typed character to the password
			password += string(char)
			fmt.Print("*") // Display an asterisk
		}
	}

	return username, password, nil
}

func getRemoteConfig() (map[string]aliasConfigV10, *probe.Error) {
	username, password, err := getUsernamePassword()
	if err != nil {
		return nil, err.Trace()
	}
	fmt.Println("Requesting remote secret vault...")
	defer fmt.Println("Requested access keys.")

	token, rerr := getUserToken(jmcVaultAddress, username, password)
	if rerr != nil {
		return nil, probe.NewError(rerr)
	}

	returnAliases := make(map[string]aliasConfigV10)

	secretPaths := strings.Split(jmcSecretsPaths, ",")
	secretMap := map[string]string{
		jmcAliasNameVKey: "",
		jmcAddressVKey:   "",
		jmcKeyVKey:       "",
		jmcSecretVKey:    "",
		jmcAPIVKey:       jmcAPIDefault,
		jmcPathVKey:      jmcPathDefault,
	}
	mustHaveKeys := [4]string{jmcAliasNameVKey, jmcAddressVKey, jmcKeyVKey, jmcSecretVKey}
	retErr := fmt.Errorf("Some errors when requesting secret engine '%s': ", jmcSecretEngine)
	hasRetError := false
	for _, secretPath := range secretPaths {
		secretPath = strings.TrimSpace(secretPath)
		secretJson, rerr := getUserSecrets(jmcVaultAddress, jmcSecretEngine, secretPath, token)
		if rerr != nil {
			retErr = fmt.Errorf("%w\nGet secret in '%s': %w\n", retErr, secretPath, rerr)
			hasRetError = true
			continue
		}

		correct := true
		for _, mustHaveKey := range mustHaveKeys {
			if mustHaveValue, ok := secretJson[mustHaveKey]; ok {
				if valueStr, ok := mustHaveValue.(string); ok {
					secretMap[mustHaveKey] = valueStr
					continue
				}
			}
			retErr = fmt.Errorf("%w\nNot found '%s' in secret '%s'\n", retErr, mustHaveKey, secretPath)
			correct = false
			hasRetError = true
			break
		}
		if !correct {
			continue
		}

		returnAliases[secretMap[jmcAliasNameVKey]] = aliasConfigV10{
			URL:       secretMap[jmcAddressVKey],
			AccessKey: secretMap[jmcKeyVKey],
			SecretKey: secretMap[jmcSecretVKey],
			API:       secretMap[jmcAPIVKey],
			Path:      secretMap[jmcPathVKey],
		}
	}

	if hasRetError {
		return returnAliases, probe.NewError(retErr)
	} else {
		return returnAliases, nil
	}
}
