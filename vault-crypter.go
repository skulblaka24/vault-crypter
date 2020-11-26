/* ###################################################################################
							Vault-Crypter Go Binary
*	Decription: This binary has been created to crypt and decrypt files locally leveraging cryptographic keys inside of HashiCorp Vault.
*	Author: Gauthier Donikian
*	Version: 0.1
*	Date: 30th November 2020
#################################################################################### */
package main

import (
	//"crypto/aes"
	//"crypto/cipher"
	//"crypto/rand"
	//"encoding/base64"
	//"encoding/json"
	"fmt"
	"os"
	//"io"
	//"io/ioutil"
	"flag"
	//"strings"
	//"time"
	//"sort"
	//"bufio"
	"strconv"

	"github.com/hashicorp/vault/api" // go get github.com/hashicorp/vault/api
	"github.com/skulblaka24/vault-crypter/functions"
)

/* ##########  Variables ########## */

//var vault_addr = os.Getenv("VAULT_ADDR")
//var vault_token string
//var vault_client *api.Client // global variable

var data_key *api.Secret
var wrapped_key string
var key_exist bool
var key_version string
var path_secret string

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

func main() {

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
		fmt.Printf("Description: Vault-crypter is a tool written using Golang to crypt/decrypt files locally using HashiCorp Vault's encryption keys\n")
	    fmt.Printf("Version: 0.1\n\n")
	    fmt.Printf("Usage: vault-crypter [OPTION]...\n\n")
	    fmt.Printf("Vault Workflow available:\n")

	    fmt.Printf("1 - Initialize Vault: $ vault-crypter -i [OPTION]...[OPTION]\n")
	    fmt.Printf("			      Optional argument: -pt -kt -pk\n")

	    fmt.Printf("2 - Crypt a file without an existing in Vault: $ vault-crypter -c [OPTION]...[OPTION]\n")
	    fmt.Printf("			      Optional argument: \n")

	    fmt.Printf("3 - Crypt a file without an existing in Vault: $ vault-crypter -c [OPTION]...[OPTION]\n")
	    fmt.Printf("			      Optional argument: \n")

	    fmt.Printf("4 - Decrypt a file with an existing in Vault: $ vault-crypter -d [OPTION]...[OPTION]\n")
	    fmt.Printf("			      Optional argument: \n")

	    fmt.Printf("\nLocal Workflow available:\n")

	    fmt.Printf("5 - Crypt a file with/without an existing local key: $ vault-crypter -m local -c [OPTION]...[OPTION]\n")
	    fmt.Printf("			      Optional argument: \n")

	    fmt.Printf("6 - Decrypt a file with an existing local key: $ vault-crypter -m local -d [OPTION]...[OPTION]\n")
	    fmt.Printf("			      Optional argument: \n")

	    fmt.Printf("\n\n")
	    fmt.Printf("Options:\n")
	    flag.PrintDefaults()
	}

	// Arguments
	mode := flag.String("m", "vault", "Mode to be used, can be local or vault")
	login_method := flag.String("l", "token", "The Vault auth login method available are: token, userpass, approle")
	
	init := flag.Bool("i", false, "Enable the transit engine, its key and the kv engine")
	path_transit := flag.String("pt", "vault-crypt-transit", "Add a custom path for the transit engine")
	key_name_transit := flag.String("kt", "key", "Key name for the transit engine")

	path_kv := flag.String("pk", "vault-crypt-kv", "Add a custom path for the kv engine")
	secret_name_kv := flag.String("sk", "", "Secret name for the stored wrapped key in the kv engine")
	secret_name_version := flag.Int("sv", 0, "Version number for the stored wrapped key in the kv engine")


	crypt := flag.Bool("c", false, "To crypt file or binary")
	crypt_input_name := flag.String("cin", "input", "Add a crypt input file name")
	crypt_output_name := flag.String("con", "encryptedfile", "Add a crypt output file name")

	decrypt := flag.Bool("d", false, "To decrypt file or binary")
	decrypt_input_name := flag.String("din", "local:encryptedfile", "Add a crypt input file name")


	useColor := flag.Bool("color", false, "Display colorized output")
	//debug := flag.Bool("v", false, "Verbose flag")
	
	flag.Parse()


	// HERE: Requirement Check: which option goes with which option

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

	// Arguments Check
	args_status := functions.CheckArgs()
	switch {
	case args_status["c"] == true && args_status["d"] == true:
		// Error Type | Message | Color | Exit type
		functions.Error("arg", "You cannot crypt and decrypt at the same time !\nPlease remove either -c ou -d", ColorRed, "1")
		os.Exit(1)
		
	}



    

	switch {

	// Error handling
	case *mode != "vault" && *mode != "local":
		fmt.Printf("Error: The mode parameter should be vault or local, exiting...")
		os.Exit(1)

	// Vault Mode Handling
	case *mode == "vault":

		// Initialize the session with Vault and the token generation
		functions.InitVault(*login_method)

		switch {

		// Initialize the transit engine, the transit key and the KV path
		case *init == true:
			functions.InitTransit(*path_transit)
			functions.CreateKeyTransit(*path_transit, *key_name_transit)
			functions.InitKV(*path_kv)

		// Handle the encryption mechanism
		case *crypt == true:

			// Check if key is in vault in kv for the workflow 3.
			if *secret_name_kv != "" && *secret_name_version != 0 {
				wrapped_key = functions.ReadSecret(*path_kv, *secret_name_kv, *secret_name_version, "kv2")
				key_exist = true
				path_secret = *secret_name_kv

				// Debug
				//fmt.Printf("WRAPPED_KEY: %v | %T\n", wrapped_key, wrapped_key)
			} else {
				// Get Wrapped Derived Key from the transit engine
				data_key = functions.GetDataKey(*key_name_transit)
				wrapped_key = fmt.Sprintf("%v", data_key.Data["ciphertext"])
				key_exist = false
				path_secret = "transit-key"

				// Debug
				//fmt.Printf("DATA_KEY: %v | %T\n", data_key, data_key)
				//fmt.Printf("WRAPPED_KEY: %v | %T\n", wrapped_key, wrapped_key)
			}

			// Unwrap the wrapped derived key
			plaintext_key := functions.DecryptString(wrapped_key, *key_name_transit)
			
			// Decode the derived key
			functions.Key = functions.DecodeBase64([]byte(plaintext_key.Data["plaintext"].(string)))
			
			if key_exist == false {
				// Save the wrapped derived key in the kv engine
				key_version = functions.WriteSecret("kv2", *path_kv+"/data/"+path_secret, data_key.Data["ciphertext"].(string) )
			} else {
				key_version = strconv.Itoa(*secret_name_version)
			}

			// Debug
			//fmt.Printf("DECRYPTED_CONTENT: %v | %T\n", plaintext_key, plaintext_key)
			//fmt.Printf("GLOBAL_KEY: %v | %T\n", functions.Key, functions.Key)
			//fmt.Printf("%v", key_version)
			
			// Crypt the file
			functions.EncryptFile(*crypt_input_name, "v"+key_version+":"+*crypt_output_name)

		case *decrypt == true:
			
			wrapped_key = functions.ReadSecret(*path_kv, *secret_name_kv, *secret_name_version, "kv2")
			
			// Unwrap the wrapped derived key
			plaintext_key := functions.DecryptString(wrapped_key, *key_name_transit)
			
			// Decode the derived key
			functions.Key = functions.DecodeBase64([]byte(plaintext_key.Data["plaintext"].(string)))
			
			// Debug
			//fmt.Printf("VERSION_KEY: %v | %T\n", *secret_name_version, *secret_name_version)
			//fmt.Printf("WRAPPED_KEY: %v | %T\n", wrapped_key, wrapped_key)
			//fmt.Printf("DECRYPTED_KEY: %v | %T\n", plaintext_key, plaintext_key)
			//fmt.Printf("GLOBAL_KEY: %v | %T\n", functions.Key, functions.Key)

			// Derypt the file
			functions.DecryptFile(*decrypt_input_name, "decryptedfile")
		} 

	// Local Mode Handling
	case *mode == "local":
		switch {

		case *crypt == true:
			functions.CheckLocalKey()

			// Debug
			//fmt.Printf("Key: %x\n", functions.Key)
			//fmt.Printf("Data: %s\n", *crypt_input_name)

			functions.EncryptFile(*crypt_input_name, "local:encryptedfile")

		case *decrypt == true:
			functions.CheckLocalKey()

			// Debug
			//fmt.Printf("Key: %x\n", functions.Key)
			//fmt.Printf("Data: %s\n", *crypt_input_name)

			functions.DecryptFile(*decrypt_input_name, "decryptedfile")
		}
	}
	
	if *useColor {
        functions.Colorize(ColorBlue, "HashiCorp Colors !!!")
    }
}

