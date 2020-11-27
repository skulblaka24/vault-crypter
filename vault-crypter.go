/* ###################################################################################
							Vault-Crypter Go Binary
*	Decription: This binary has been created to crypt and decrypt files locally leveraging cryptographic keys inside of HashiCorp Vault.
*	Author: Gauthier Donikian
*	Version: 0.1
*	Date: 30th November 2020
#################################################################################### */
package main

import (
	"fmt"
	"os"
	"flag"
	"strconv"

	//"github.com/hashicorp/vault/api" // go get github.com/hashicorp/vault/api
	"github.com/skulblaka24/vault-crypter/functions"
)

/* ##########  Variables ########## */

var wrapped_key string
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

	    fmt.Printf("1 - Initialize Vault (Optional argument: -pt -kt -pk): \n")
	    fmt.Printf(" 	$ vault-crypter -i [OPTION]...[OPTION]\n\n")

	    fmt.Printf("2 - Crypt a file without an existing key in Vault (Optional argument: -pt -kt -pk -sk -cin -con ): \n")
	    fmt.Printf(" 	$ vault-crypter -c [OPTION]...[OPTION]\n\n")

	    fmt.Printf("3 - Crypt a file with an existing key in Vault (Optional argument: -pt -kt -pk -sk -sv -cin -con): \n")
	    fmt.Printf(" 	$ vault-crypter -c [OPTION]...[OPTION]\n\n")

	    fmt.Printf("4 - Decrypt a file with an existing key in Vault (Required: -din -sk -sv, Optional: -pt -kt -pk): \n")
	    fmt.Printf(" 	$ vault-crypter -d [OPTION]...[OPTION]\n\n")

	    fmt.Printf("\nLocal Workflow available:\n")

	    fmt.Printf("5 - Crypt a file with/without an existing local key (Optional argument: -cin): \n")
	    fmt.Printf(" 	$ vault-crypter -m local -c [OPTION]...[OPTION]\n\n")

	    fmt.Printf("6 - Decrypt a file with an existing local key (Optional argument: -din): \n")
	    fmt.Printf(" 	$ vault-crypter -m local -d [OPTION]...[OPTION]\n\n")

	    fmt.Printf("\n")

		fmt.Printf("\n")
		fmt.Printf("Environment variables to provide vault-crypter with Vault connection info:")
		fmt.Printf("All original Vault client environment variable are be compatible...")
		fmt.Printf("VAULT_ADDR - REQUIRED - Must be the Vault cluster active node - Format: https://FQDN:8200")
		fmt.Printf("VAULT_CACERT - CA can be specified to verify vault https certificate")
		fmt.Printf("VAULT_SKIP_VERIFY - To avoid ssl verification")
		fmt.Printf("VAULT_NAMESPACE - To set the namespace")
		fmt.Printf("VAULT_TOKEN - If you are using the token auth method on Vault")
		fmt.Printf("VAULT_ROLE_ID - If you are using the approle auth method on Vault")
		fmt.Printf("VAULT_SECRET_ID - If you are using the approle auth method on Vault")
		fmt.Printf("VAULT_USERNAME - If you are using the userpass auth method on Vault")
		fmt.Printf("VAULT_PASSWORD - If you are using the userpass auth method on Vault")
		fmt.Printf("\n")


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
	secret_name_kv := flag.String("sk", "transit-key", "Secret name for the stored wrapped key in the kv engine")
	secret_name_version := flag.Int("sv", 0, "Version number for the stored wrapped key in the kv engine")

	crypt := flag.Bool("c", false, "To crypt file or binary")
	crypt_input_name := flag.String("cin", "input", "Add a crypt input file name")
	crypt_output_name := flag.String("con", "encryptedfile", "Add a crypt output file name")

	decrypt := flag.Bool("d", false, "To decrypt file or binary")
	decrypt_input_name := flag.String("din", "local:encryptedfile", "Add a crypt input file name")

	useColor := flag.Bool("color", false, "Display colorized output")
	debug := flag.Bool("v", false, "Verbose flag")
	
	flag.Parse()


	// Environment Variable Check
	switch {
	case os.Getenv("VAULT_ADDR") == "":
		functions.Error("env", "\nYou need to set the environment variable for the vault adress: VAULT_ADDR", *useColor, "1")
	case *login_method == "token" && os.Getenv("VAULT_TOKEN") == "":
		functions.Error("env", "\nYou need to set the token environment variable: VAULT_TOKEN", *useColor, "1")
	case *login_method == "approle" && (os.Getenv("VAULT_ROLE_ID") == "" || os.Getenv("VAULT_SECRET_ID") == ""):
		functions.Error("env", "\nYou need to set two mandatory environment variables: VAULT_ROLE_ID, VAULT_SECRET_ID", *useColor, "1")
	case *login_method == "userpass" && (os.Getenv("VAULT_USERNAME") == "" || os.Getenv("VAULT_PASSWORD") == ""):
		functions.Error("env", "\nYou need to set two mandatory environment variables: VAULT_USERNAME, VAULT_PASSWORD", *useColor, "1")
	}

	// Arguments Check
	args_status := functions.CheckArgs()
	switch {
	case args_status["c"] == true && args_status["d"] == true:
		functions.Error("arg", "\nYou cannot crypt and decrypt at the same time !\nPlease remove either -c ou -d", *useColor, "1")
	
	case args_status["i"] == true && (args_status["sk"] == true || args_status["sv"] == true || args_status["cin"] == true || args_status["con"] == true || args_status["din"] == true):
		functions.Error("arg", "\nThe only options available for -i are -pk -pt -kt !", *useColor, "1")
	
	case args_status["c"] == true && args_status["din"] == true:
		functions.Error("arg", "\nThe -din argument is not available for -c !", *useColor, "1")
	
	case args_status["d"] == true && args_status["cin"] == true && args_status["con"] == true:
		functions.Error("arg", "\nThe -cin and -con argument are not available for -d !", *useColor, "1")
	
	case args_status["d"] == true && args_status["din"] == false && *mode == "vault":
		functions.Error("arg", "Must specify input filename with -din !", *useColor, "1")
	
	case args_status["sv"] == true && args_status["sk"] == false:
		functions.Error("arg", "\nIf the secret version (-sv) is specified, you must add the parameter -sk !", *useColor, "1")
	
	//case (args_status["din"] == true || args_status["sv"] == true || args_status["sk"] == true || args_status["kt"] == true || args_status["pt"] == true || args_status["pk"] == true || args_status["cin"] == true || args_status["con"] == true) && (args_status["c"] == false || args_status["d"] == false || args_status["i"] == false):
	//	functions.Error("arg", "\nYou cannot use optional argument without -c or -d or -i\nPlease add one of them depending on the action wanted", *useColor, "1")
	}

	// Main
	switch {

	// Error handling
	case *mode != "vault" && *mode != "local":
		functions.Error("arg", "The mode parameter should be vault or local", *useColor, "1")

	// Vault Mode Handling
	case *mode == "vault":

		// Initialize the session with Vault and the token generation
		functions.InitVault(*login_method)

		switch {

		// Initialize the transit engine, the transit key and the KV path
		case *init == true:
			functions.EnableTransit(*path_transit)
			functions.CreateKeyTransit(*path_transit, *key_name_transit)
			functions.EnableKV(*path_kv)

		// Handle the encryption mechanism
		case *crypt == true:

			wrapped_key, key_exist, data_key := functions.CheckKey(*mode, *secret_name_version, *secret_name_kv, *path_kv, *path_transit, *key_name_transit)

			// Unwrap the wrapped derived key
			plaintext_key := functions.DecryptString(*path_transit, wrapped_key, *key_name_transit)
			
			// Decode the derived key
			functions.Key = functions.DecodeBase64([]byte(plaintext_key.Data["plaintext"].(string)))
			
			if key_exist == false {
				// Save the wrapped derived key in the kv engine
				key_version = functions.WriteSecret("kv2", *path_kv+"/data/"+*secret_name_kv, data_key.Data["ciphertext"].(string) )
			} else {
				key_version = strconv.Itoa(*secret_name_version)
			}

			// Debug
			if *debug {fmt.Printf("DECRYPTED_CONTENT: %v | %T\n", plaintext_key, plaintext_key)
			fmt.Printf("GLOBAL_KEY: %v | %T\n", functions.Key, functions.Key)
			fmt.Printf("KEY_VERSION: %v | %T\n", key_version, key_version)}
			
			// Crypt the file
			functions.EncryptFile(*crypt_input_name, "v"+key_version+":"+*crypt_output_name)

		case *decrypt == true:
			
			wrapped_key = functions.ReadSecret(*path_kv, *secret_name_kv, *secret_name_version, "kv2")
			
			// Unwrap the wrapped derived key
			plaintext_key := functions.DecryptString(*path_transit, wrapped_key, *key_name_transit)
			
			// Decode the derived key
			functions.Key = functions.DecodeBase64([]byte(plaintext_key.Data["plaintext"].(string)))
			
			// Debug
			if *debug {fmt.Printf("VERSION_KEY: %v | %T\n", *secret_name_version, *secret_name_version)
			fmt.Printf("WRAPPED_KEY: %v | %T\n", wrapped_key, wrapped_key)
			fmt.Printf("DECRYPTED_KEY: %v | %T\n", plaintext_key, plaintext_key)
			fmt.Printf("GLOBAL_KEY: %v | %T\n", functions.Key, functions.Key)}

			// Derypt the file
			functions.DecryptFile(*decrypt_input_name, "decryptedfile")
		} 

	// Local Mode Handling
	case *mode == "local":
		switch {

		case *crypt == true:
			functions.CheckKey(*mode, *secret_name_version, *secret_name_kv, *path_kv, *path_transit, *key_name_transit)

			// Debug
			//fmt.Printf("Key: %x\n", functions.Key)
			//fmt.Printf("Data: %s\n", *crypt_input_name)

			functions.EncryptFile(*crypt_input_name, "local:encryptedfile")

		case *decrypt == true:
			functions.CheckKey(*mode, *secret_name_version, *secret_name_kv, *path_kv, *path_transit, *key_name_transit)

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

