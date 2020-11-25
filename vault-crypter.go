/* ###################################################################################
							Vault-Crypter Go Binary
*	Decription: This binary has been created to crypt and decrypt files locally leveraging cryptographic keys inside of HashiCorp Vault.
*	Author: Gauthier Donikian
*	Version: 0.1
*	Date: 30th November 2020
#################################################################################### */
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"io"
	"io/ioutil"
	"flag"
	"strings"
	"time"
	"sort"
	"bufio"
	"strconv"

	vault "github.com/hashicorp/vault/api" // go get github.com/hashicorp/vault/api
	"github.com/ryanuber/columnize"
	"github.com/mitchellh/cli"
	//"github.com/skulblaka24/vault-crypter"
)

/* ##########  Variables ########## */

var vault_addr = os.Getenv("VAULT_ADDR")
var vault_token string
var vault_client *vault.Client // global variable

var data_key *vault.Secret
var wrapped_key string
var key_exist bool
var key_version string
var path_secret string
var key []byte

type Color string

const (
    ColorBlack  Color = "\u001b[30m"
    ColorRed          = "\u001b[31m"
    ColorGreen        = "\u001b[32m"
    ColorYellow       = "\u001b[33m"
    ColorBlue         = "\u001b[34m"
    ColorMagenta      = "\u001b[35m"
    ColorCyan         = "\u001b[36m"
    ColorWhite        = "\u001b[37m"
    ColorReset        = "\u001b[0m"
)

/* ##########  !Variables ########## */

func colorize(color Color, message string) {
    fmt.Println(string(color), message, string(ColorReset))
}

type VaultUI struct {
	cli.Ui
	format string
}

// Used for the lookup ouput function
const (
	// hopeDelim is the delimiter to use when splitting columns. We call it a
	// hopeDelim because we hope that it's never contained in a secret.
	hopeDelim = "♨"
)

// Used for the lookup ouput function
func looksLikeDuration(k string) bool {
	return k == "period" || strings.HasSuffix(k, "_period") ||
		k == "ttl" || strings.HasSuffix(k, "_ttl") ||
		k == "duration" || strings.HasSuffix(k, "_duration") ||
		k == "lease_max" || k == "ttl_max"
}

// Used for the lookup ouput function
// humanDuration prints the time duration without those pesky zeros.
func humanDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}

	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if idx := strings.Index(s, "h0m"); idx > 0 {
		s = s[:idx+1] + s[idx+3:]
	}
	return s
}

// Used for the lookup ouput function
// humanDurationInt prints the given int as if it were a time.Duration  number
// of seconds.
func humanDurationInt(i interface{}) interface{} {
	switch i.(type) {
	case int:
		return humanDuration(time.Duration(i.(int)) * time.Second)
	case int64:
		return humanDuration(time.Duration(i.(int64)) * time.Second)
	case json.Number:
		if i, err := i.(json.Number).Int64(); err == nil {
			return humanDuration(time.Duration(i) * time.Second)
		}
	}

	// If we don't know what type it is, just return the original value
	return i
}

// Used for the lookup ouput function
func tableOutput(list []string, c *columnize.Config) string {
	if len(list) == 0 {
		return ""
	}

	delim := "|"
	if c != nil && c.Delim != "" {
		delim = c.Delim
	}

	underline := ""
	headers := strings.Split(list[0], delim)
	for i, h := range headers {
		h = strings.TrimSpace(h)
		u := strings.Repeat("-", len(h))

		underline = underline + u
		if i != len(headers)-1 {
			underline = underline + delim
		}
	}

	list = append(list, "")
	copy(list[2:], list[1:])
	list[1] = underline

	return columnOutput(list, c)
}

// Used for the lookup ouput function
// columnOuput prints the list of items as a table with no headers.
func columnOutput(list []string, c *columnize.Config) string {
	if len(list) == 0 {
		return ""
	}

	if c == nil {
		c = &columnize.Config{}
	}
	if c.Glue == "" {
		c.Glue = "    "
	}
	if c.Empty == "" {
		c.Empty = "n/a"
	}

	return columnize.Format(list, c)
}

// Used for the lookup ouput function
func formatOutput(data map[string]interface{}){
	out := make([]string, 0, len(data)+1)
	if len(data) > 0 {
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			v := data[k]

			// If the field "looks" like a TTL, print it as a time duration instead.
			if looksLikeDuration(k) {
				v = humanDurationInt(v)
			}

			out = append(out, fmt.Sprintf("%s %s %v", k, hopeDelim, v))
		}
	}

	// If we got this far and still don't have any data, there's nothing to print,
	// sorry.
	if len(out) == 0 {
		os.Exit(1)
	}

	// Prepend the header
	out = append([]string{"Key" + hopeDelim + "Value"}, out...)
	
	//fmt.Println(out)

	ui := &VaultUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader:      bufio.NewReader(os.Stdin),
				Writer:      os.Stdout,
				ErrorWriter: os.Stderr,
			},
		},
		format: "table",
	}

	ui.Output(tableOutput(out, &columnize.Config{
		Delim: hopeDelim,
	}))
}

func lookupToken(vault_token string){
	//fmt.Printf("VAULT_TOKEN: %s | %v | %T \n:", vault_token, vault_token, vault_token)

	// Waits a second in case, we generated the token from a secondary node.
	time.Sleep(1 * time.Second)

	// Get the token infos
	lookup, err := vault_client.Auth().Token().Lookup(vault_token)
	if err != nil {
		fmt.Println(err)
	}

	//fmt.Println(lookup.Data)

	formatOutput(lookup.Data)
}

func userpassLogin(username string, password string) (string) {

	options := map[string]interface{}{
		"password": password,
	}
	path := fmt.Sprintf("auth/userpass/login/%s", username)

	secret, err := vault_client.Logical().Write(path, options)
	if err != nil {
		fmt.Println(err)
	}

	return secret.Auth.ClientToken
}

func approleLogin(vault_role_id string, vault_secret_id string) (string) {

	options := map[string]interface{}{
		"role_id":   vault_role_id,
		"secret_id": vault_secret_id,
	}
	path := fmt.Sprintf("auth/approle/login")

	secret, err := vault_client.Logical().Write(path, options)
	if err != nil {
		fmt.Println(err)
	}
	return secret.Auth.ClientToken
}

func initVault(authType string) (string){
	
	// Config can be set through ENV before any step and creating a new client
    //os.Setenv("VAULT_TOKEN", "s.JLxf3Iun7m2FWJD5ZgSE3p4J")

	//fmt.Println("### Step: Vault Initialisation:")
	config := &vault.Config{
		Address: vault_addr,
	}
	client, err := vault.NewClient(config)
	if err != nil {
		fmt.Println(err)
	}
	vault_client = client
	
	switch {
	case authType != "token" && authType != "userpass" && authType != "approle":
		fmt.Println("Error: This auth method is not supported, the one supported are: token, userpass, approle")
		os.Exit(1)

	case authType == "token":
		//fmt.Println("authType: token")

		vault_token = os.Getenv("VAULT_TOKEN")
		if vault_token == "" {
			fmt.Println("Error: You need to set the token environment variable: VAULT_TOKEN")
			os.Exit(1)
		}
		//fmt.Printf("Token: %s\n", vault_token)

	case authType == "userpass":
		//fmt.Println("authType: userpass")

		vault_username := os.Getenv("VAULT_USERNAME")
		vault_password := os.Getenv("VAULT_PASSWORD")
		if vault_username == "" || vault_password == "" {
			fmt.Println("Error: You need to set two mandatory environment variables: VAULT_USERNAME, VAULT_PASSWORD")
			os.Exit(1)
		}
		
		vault_token = userpassLogin(vault_username, vault_password)

		//fmt.Printf("Token: %s\n", vault_token)
		
	case authType == "approle":
		//fmt.Println("authType: approle")

		vault_role_id := os.Getenv("VAULT_ROLE_ID")
		vault_secret_id := os.Getenv("VAULT_SECRET_ID")
		if vault_role_id == "" || vault_secret_id == "" {
			fmt.Println("Error: You need to set two mandatory environment variables: VAULT_ROLE_ID, VAULT_SECRET_ID")
			os.Exit(1)
		}

		vault_token = approleLogin(vault_role_id, vault_secret_id)

		//fmt.Printf("Token: %s\n", vault_token)
	}

	vault_client.SetToken(vault_token)
	
	return vault_token
}

func readSecret(path string, secret string, version int, kversion string) string {
	var wrapped_key string

	// KV Version 1
	if kversion == "kv1" {

		request, err := vault_client.Logical().Read(path+"/"+secret)
		if err != nil {
			fmt.Println(err)
		}
		
		// Debug
		//fmt.Printf("Key:%s | %v | %T\n", request, request.Data["key"], request)

		// Output the value from the token key
		wrapped_key = fmt.Sprintf("%v", request.Data["key"])

	// KV Version 2
	} else if kversion == "kv2" {
		
		s_version := strconv.Itoa(version)

		//fmt.Printf("Version: %s | %v | %T\n", s_version, s_version, s_version)

		options := make(map[string][]string)
		options["version"] = []string{s_version}
		
		request, err := vault_client.Logical().ReadWithData(path+"/data/"+secret, options)
		if err != nil {
			// If the path or version is incorrect, the program will panic before printing the error.
			fmt.Println(err)
		}
		
		// Debug
		//fmt.Printf("Key:%s | %v | %T\n", request, request.Data["data"], request)

		// Convert the output to a map interface.
		data := request.Data["data"].(map[string]interface{})

		// Output the value from the token key
		wrapped_key = fmt.Sprintf("%v", data["key"])

	}

	return wrapped_key
}

func getDataKey(key string) (*vault.Secret){

	context := map[string]interface{}{
		"context": "Ym9uam91cg==",
	}

	// Can also be transit/datakey/wrapped/
	datakey, err := vault_client.Logical().Write("transit/datakey/plaintext/" + key, context)
	if err != nil {
		fmt.Println(err)
	}

	// Debug
	//fmt.Printf("Wrapped_datakey: %s\n", datakey.Data["ciphertext"])
	//fmt.Printf("Plaintext_datakey: %s\n", datakey.Data["plaintext"])
	
	return datakey
}

func decryptString(ciphertext interface {}, key string) (*vault.Secret) {

	decrypted_contents, err := vault_client.Logical().Write("transit/decrypt/" + key, map[string]interface{} {
		"ciphertext": ciphertext,
		"context": "Ym9uam91cg==",
	})
	if err != nil {
		fmt.Printf("Error decrypting file: %s", err)
	}
	
	//fmt.Printf("Decrypted: %s\n", decrypted_contents.Data["plaintext"])

	return decrypted_contents
}

func writeSecret(kversion string, path string, key string) string {

	// Version 1
	if kversion == "kv1" {
		options := map[string]interface{}{
				"key":key,
		}
		//fmt.Println(options)

		_, err := vault_client.Logical().Write(path, options)
		if err != nil {
			fmt.Println(err)
		}
		return "1"

	// Version 2
	} else if kversion == "kv2" {
		options := map[string]interface{}{
			"data": map[string]interface{}{
				"key":key,
			},
		}

		// Debug
		//fmt.Println(options)

		output, err := vault_client.Logical().Write(path, options)
		if err != nil {
			fmt.Println(err)
		}
		kv_version := fmt.Sprintf("%v", output.Data["version"])
		if kv_version == "4294967285" {
			fmt.Printf("Error: The KV Engine will start deleting older versions as you've reach the maximum!")
			fmt.Printf("Error: You have ten key version left, please consider changing the kv path")
		}
		
		return kv_version
	}
	return "1"

}

func generateBufferForError (err error, line int) string {

	err_string := fmt.Sprintf("%v",err)

	buffer := [][]string{}
	block := []string{}
	scanner := bufio.NewScanner(strings.NewReader(err_string))
	for scanner.Scan() {
		l := scanner.Text()

		if len(l) != 0 {
			block = append(block, l)
			continue
		}

		if len(l) == 0 && len(block) != 0 {
			buffer = append(buffer, block)
			block = []string{}
			continue
		}

		if len(l) == 0 {
			block = []string{}
			continue
		}

	}

	if len(block) != 0 {
		buffer = append(buffer, block)
		block = []string{}
	}

	error := fmt.Sprintf("%v", buffer[line])

	return error

}

func initTransit (path string) {

	options := map[string]interface{}{
			"type": "transit",
			"description": "Transit Engine to serve the vault-crypter binary",
	}

	_, err := vault_client.Logical().Write("sys/mounts/" + path, options)

	if err != nil {
		error := generateBufferForError(err, 2)
		if error != "[* path is already in use at "+path+"/]" {
			fmt.Println(err)
		}
	}
}

func initKV (path string) {

	options := map[string]interface{}{
			"type": "kv-v2",
			"description": "KV Engine to serve the vault-crypter binary",
	}

	_, err := vault_client.Logical().Write("sys/mounts/" + path, options)
	if err != nil {
		error := generateBufferForError(err, 2)
		if error != "[* path is already in use at "+path+"/]" {
			fmt.Println(err)
		}
	}

	options_configuration := map[string]interface{}{
		"max_versions": -1,
	}

	_, err = vault_client.Logical().Write(path + "/config", options_configuration)
	if err != nil {
		fmt.Println(err)
	}
}

func createKeyTransit (path string, key_name string) {

	options := map[string]interface{}{}
	_, err := vault_client.Logical().Write(path + "/keys/" + key_name, options)

	if err != nil {
		fmt.Println(err)
		/*error := generateBufferForError(err, 2)
		if error != "[* path is already in use at "+path+"/]" {
			fmt.Println(err)
		}*/
	}
}

func main() {
	// Initially there is 124 lines of code in the enc.go

	/* #####
	Verify env variables here
	VAULT_SKIP_VERIFY
	VAULT_ADDR
	VAULT_TOKEN
	VAULT_CA_CERT
	VAULT_ADDR=https://v2.starfly.fr:8200
	VAULT_CACERT=/Users/gauth/Vault/Lab/raft-cluster/certs/ca.crt
	VAULT_ROLE_ID=5746f456-da56-52e7-8ebc-d957f2c1f4ff
	VAULT_SECRET_ID=3c348606-d074-1c85-eb5b-eae06a489c74
	VAULT_USERNAME=admin
	VAULT_PASSWORD=Skulblaka24
	VAULT_TOKEN=s.JLxf3Iun7m2FWJD5ZgSE3p4J
	##### */

	// Help Menu
	flag.Usage = func() {
		fmt.Printf("\n")
		fmt.Printf(`            '/'    '/'            
         -+hHH'    .HHh+.         
     ':smHHHHH'    .HHHH+ -:'     
   /hHHHHHHho-     .HHHH+ +HHh/   
   hHHHms:' -+'    .HHHH+ +HHHh    _   _  ___  _   _ _    _____      _____ ________   _______ _____ ___________ 
   hHHH/ -ymHH.    .HHHH+ +HHHh   | | | |/ _ \| | | | |  |_   _|    /  __ \| ___ \ \ / / ___ \_   _|  ___| ___ \
   hHHH/ +HHHH-....-HHHH+ +HHHh   | | | / /_\ \ | | | |    | |______| /  \/| |_/ /\ V /| |_/ / | | | |__ | |_/ /
   hHHH/ +HHHHHHHHHHHHHH+ +HHHh   | | | |  _  | | | | |    | |______| |    |    /  \ / |  __/  | | |  __||    / 
   hHHH/ +HHHHHHHHHHHHHH+ +HHHh   \ \_/ / | | | |_| | |____| |      | \__/\| |\ \  | | | |     | | | |___| |\ \ 
   hHHH/ +HHHH-....-HHHH+ +HHHh    \___/\_| |_/\___/\_____/\_/       \____/\_| \_| \_/ \_|     \_/ \____/\_| \_|
   hHHH/ +HHHH.    .HHms- +HHHh   ______________________________________________________________________________
   hHHH/ +HHHH.    '+. '/smHHHh   
   /yHH/ +HHHH.     :odHHHHHHh/   
     ':- +HHHH.    .HHHHHds:'     
         .+hHH.    .HHh+.         
            ':'    ':' 
  
                                                                    `)
		fmt.Printf("\n")
		fmt.Printf("Description: Vault-crypter is a tool written using Golang to crypt/decrypt files locally using HashiCorp Vault's encryption keys\n\n")
	    fmt.Printf("Usage: vault-crypter [OPTION]...\n\n")
	    fmt.Printf("Workflow available:\n")
	    fmt.Printf("1 - Initialize Vault: vault-crypter -i [OPTION]...[OPTION]\n")
	    fmt.Printf("			      Optional options: -pt -kt -pk\n")


	    fmt.Printf("\n\n")
	    flag.PrintDefaults()
	}

	// Arguments
	login_method := flag.String("l", "token", "The Vault auth login method available are: token, userpass, approle")
	mode := flag.String("m", "vault", "Mode to be used, can be local or vault")
	
	init := flag.Bool("i", false, "Default Value is Transit - Enable the transit engine")
	path_transit := flag.String("pt", "vault-crypt-transit", "Default Value is vault-crypt-transit - Add a custom path for the transit engine")
	key_name_transit := flag.String("kt", "key", "Key name for the transit engine")

	path_kv := flag.String("pk", "vault-crypt-kv", "Default Value is vault-crypt-kv - Add a custom path for the kv engine")
	secret_name_kv := flag.String("sk", "", "Secret name for the stored wrapped key in the kv engine")
	secret_name_version := flag.Int("sv", 0, "Version number for the stored wrapped key in the kv engine")


	crypt := flag.Bool("c", false, "To crypt file or binary")
	//crypt_version := flag.String("cv", "1", "Default Value is input - Add a crypt input file name")
	crypt_input_name := flag.String("cin", "input", "Default Value is input - Add a crypt input file name")
	crypt_output_name := flag.String("con", "encryptedfile", "Default Value is encryptedfile - Add a crypt output file name")
	//context := flag.String("ct", "context", "Default Value is context - Add a context to crypt/decrypt")

	decrypt := flag.Bool("d", false, "To decrypt file or binary")
	decrypt_input_name := flag.String("din", "local:encryptedfile", "Default Value is input - Add a crypt input file name")


	useColor := flag.Bool("color", false, "Display colorized output")
	//debug := flag.Bool("v", false, "Verbose flag")
	
	flag.Parse()


	// HERE: Requirement Check: which option goes with which option


	switch {

	// Error handling
	case *mode != "vault" && *mode != "local":
		fmt.Printf("Error: The mode parameter should be vault or local, exiting...")
		os.Exit(1)

	// Vault Mode Handling
	case *mode == "vault":

		// Initialize the session with Vault and the token generation
		initVault(*login_method)

		switch {

		// Initialize the transit engine, the transit key and the KV path
		case *init == true:
			initTransit(*path_transit)
			createKeyTransit(*path_transit, *key_name_transit)
			initKV(*path_kv)

		// Handle the encryption mechanism
		case *crypt == true:

			// Check if key is in vault in kv for the workflow 3.
			if *secret_name_kv != "" && *secret_name_version != 0 {
				wrapped_key = readSecret(*path_kv, *secret_name_kv, *secret_name_version, "kv2")
				key_exist = true
				path_secret = *secret_name_kv

				// Debug
				//fmt.Printf("%v", wrapped_key)
			} else {
				// Get Wrapped Derived Key from the transit engine
				data_key = getDataKey(*key_name_transit)
				wrapped_key = fmt.Sprintf("%v", data_key.Data["ciphertext"])
				key_exist = false
				path_secret = "transit-key"

				// Debug
				//fmt.Printf("%v", wrapped_key)
			}

			// Unwrap the wrapped derived key
			decrypted_contents := decryptString(wrapped_key, *key_name_transit)
			
			// Decode the derived key
			key = decodeBase64_string(decrypted_contents.Data["plaintext"].(string))
			
			// Debug
			//fmt.Printf("%v", key)

			if key_exist == false {
				// Save the wrapped derived key in the kv engine
				key_version = writeSecret("kv2", *path_kv+"/data/"+path_secret, data_key.Data["ciphertext"].(string) )
			} else {
				key_version = strconv.Itoa(*secret_name_version)
			}

			// Debug
			//fmt.Printf("%v", key_version)
			
			// Crypt the file
			encryptFile(*crypt_input_name, "v"+key_version+":"+*crypt_output_name)
		case *decrypt == true:

			wrapped_key = readSecret(*path_kv, *secret_name_kv, *secret_name_version, "kv2")

			// Unwrap the wrapped derived key
			decrypted_contents := decryptString(wrapped_key, *key_name_transit)
			
			// Decode the derived key
			key = decodeBase64_string(decrypted_contents.Data["plaintext"].(string))
			
			// Debug
			//fmt.Printf("%v", key)
			
			// Derypt the file
			decryptFile(*decrypt_input_name, "decryptedfile")
		} 

	// Local Mode Handling
	case *mode == "local":
		switch {

		case *crypt == true:
			/*checkLocalKey()

			// Debug
			//fmt.Printf("Key: %x\n", key)
			//fmt.Printf("Data: %s\n", *crypt_input_name)

			encryptFile(*crypt_input_name, "local:encryptedfile")*/
			message := functions.PrintValue()
			fmt.Println(message)

		case *decrypt == true:
			checkLocalKey()

			// Debug
			//fmt.Printf("Key: %x\n", key)
			//fmt.Printf("Data: %s\n", *crypt_input_name)

			decryptFile(*decrypt_input_name, "decryptedfile")
		}
	}
	
	if *useColor {
        colorize(ColorBlue, "HashiCorp Colors !!!")
        colorize(ColorYellow, "HashiCorp Colors !!!")
        colorize(ColorGreen, "HashiCorp Colors !!!")
        colorize(ColorRed, "HashiCorp Colors !!!")
        colorize(ColorCyan, "HashiCorp Colors !!!")
        colorize(ColorMagenta, "HashiCorp Colors !!!")
        colorize(ColorWhite, "HashiCorp Colors !!!")
        colorize(ColorBlack, "HashiCorp Colors !!!")
    }
}

func rand_str(str_size int) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, str_size)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func createPrivKey() []byte {
	newkey := []byte(rand_str(32))
	err := ioutil.WriteFile("key", newkey, 0644)
	if err != nil {
		fmt.Printf("Error creating Key file!")
		os.Exit(0)
	}
	return newkey
}

func checkLocalKey() {
	thekey, err := ioutil.ReadFile("key") //Check to see if a key was already created
	fmt.Printf("Before conversion Key: %x\n", thekey)
        if err != nil {
                key = createPrivKey() //If not, create one
        } else {
                //key = thekey //If so, set key as the key found in the file
        		key = decodeBase64(thekey)
        }
}

func encryptFile(inputfile string, outputfile string) {
	b, err := ioutil.ReadFile(inputfile) //Read the target file
        if err != nil {
                fmt.Printf("Unable to open the input file!\n")
                os.Exit(0)
        }
	ciphertext := encrypt(key, b)
        //fmt.Printf("%x\n", ciphertext)
        err = ioutil.WriteFile(outputfile, ciphertext, 0644)
        if err != nil {
                fmt.Printf("Unable to create encrypted file!\n")
                os.Exit(0)
        }
}


func decryptFile(inputfile string, outputfile string) {
	z, err := ioutil.ReadFile(inputfile)
	result := decrypt(key, z)
	//fmt.Printf("Decrypted: %s\n", result)
	fmt.Printf("Decrypted file was created with file permissions 0777\n")
	err = ioutil.WriteFile(outputfile, result, 0777)
	if err != nil {
		fmt.Printf("Unable to create decrypted file!\n")
		os.Exit(0)
	}
}

func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func decodeBase64(b []byte) []byte {
	data, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		fmt.Printf("Error: Bad Key!\n")
		os.Exit(0)
	}
	return data
}

// New base64 decoding function, will slowly decomission the decodeBase64 one.
func decodeBase64_string(b string) []byte {
	data, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		fmt.Printf("Error: Cannot decrypt string input\n")
		os.Exit(0)
	}
	return data
}

func encrypt(key, text []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	b := encodeBase64(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], b)
	return ciphertext
}
func decrypt(key, text []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(text) < aes.BlockSize {
		fmt.Printf("Error!\n")
		os.Exit(0)
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return decodeBase64(text)
}
