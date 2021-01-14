/* ###################################################################################
							Vault-Crypter Go Binary
*	Decription: This binary has been created to crypt and decrypt files locally leveraging cryptographic keys inside of HashiCorp Vault.
*	Author: Gauthier Donikian
*	Version: 0.1
*	Date: 30th November 2020
*	To be added:
		- Logging system to be able to log to a file
#################################################################################### */
package main

import (
	"fmt"
	"os"
	"flag"
	"strconv"
	"github.com/skulblaka24/vault-crypter/functions"
)

var wrapped_key string
var key_version string
var path_secret string

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

	    fmt.Printf("  1 - Initialize Vault (Optional argument: -pt -kt -pk): \n")
	    fmt.Printf("   $ vault-crypter -i [OPTION]...[OPTION]\n\n")

	    fmt.Printf("  2 - Crypt a file without an existing key in Vault (Optional argument: -p -pt -kt -pk -sk -cin -con ): \n")
	    fmt.Printf("   $ vault-crypter -c [OPTION]...[OPTION]\n\n")

	    fmt.Printf("  3 - Crypt a file with an existing key in Vault (Required argument: -sv, Optional: -p -pt -kt -pk -sk -cin -con): \n")
	    fmt.Printf("   $ vault-crypter -c [OPTION]...[OPTION]\n\n")

	    fmt.Printf("  4 - Decrypt a file with an existing key in Vault (Required argument: -din -sk -sv, Optional: -p -pt -kt -pk -don): \n")
	    fmt.Printf("   $ vault-crypter -d [OPTION]...[OPTION]\n\n")

	    fmt.Printf("\nLocal Workflow available:\n")

	    fmt.Printf("  1 - Crypt a file with/without an existing local key (Required argument: -m, Optional: -p -cin -con): \n")
	    fmt.Printf("  $ vault-crypter -m local -c [OPTION]...[OPTION]\n\n")

	    fmt.Printf("  2 - Decrypt a file with an existing local key (Required argument: -m, Optional: -p -din -don): \n")
	    fmt.Printf("   $ vault-crypter -m local -d [OPTION]...[OPTION]\n\n")

	    fmt.Printf("\n")

		fmt.Printf("Environment variables to provide vault-crypter with Vault connection info:\n")
		fmt.Printf("  All original Vault client environment variable should be compatible...\n")
		fmt.Printf("  VAULT_ADDR - REQUIRED - Must be the Vault cluster active node - Format: https://FQDN:8200\n")
		fmt.Printf("  VAULT_CACERT - CA can be specified to verify vault https certificate\n")
		fmt.Printf("  VAULT_SKIP_VERIFY - To avoid ssl verification\n")
		fmt.Printf("  VAULT_NAMESPACE - To set the namespace\n")
		fmt.Printf("  VAULT_TOKEN - If you are using the token auth method on Vault\n")
		fmt.Printf("  VAULT_ROLE_ID - If you are using the approle auth method on Vault\n")
		fmt.Printf("  VAULT_SECRET_ID - If you are using the approle auth method on Vault\n")
		fmt.Printf("  VAULT_USERNAME - If you are using the userpass auth method on Vault\n")
		fmt.Printf("  VAULT_PASSWORD - If you are using the userpass auth method on Vault\n")
		fmt.Printf("\n\n")


	    fmt.Printf("Options:\n")
	    flag.PrintDefaults()
	}

	// Arguments
	mode := flag.String("m", "vault", "Mode to be used, can be local or vault")
	login_method := flag.String("l", "token", "The Vault auth login method available are: token, userpass, approle")
	
	init := flag.Bool("i", false, "Enable the transit engine, its key and the kv engine")
	lookup := flag.Bool("lookup", false, "Works alone, with or without color")
	path_transit := flag.String("pt", "vault-crypter-transit", "Add a custom path for the transit engine")
	key_name_transit := flag.String("kt", "key", "Key name for the transit engine")

	path_kv := flag.String("pk", "vault-crypter-kv", "Add a custom path for the kv engine")
	secret_name_kv := flag.String("sk", "transit-key", "Secret name for the stored wrapped key in the kv engine")
	secret_name_version := flag.Int("sv", 0, "Version number for the stored wrapped key in the kv engine")

	path := flag.String("p", "./", "Add a path to retrieve and create crypted and decrypt files. Don't forget the / at the end !")

	crypt := flag.Bool("c", false, "To crypt file or binary")
	crypt_input_name := flag.String("cin", "input", "Add a crypt input file name without a path, just the name !")
	crypt_output_name := flag.String("con", "encryptedfile", "Add a crypt output file name without a path, just the name !")

	decrypt := flag.Bool("d", false, "To decrypt file or binary")
	decrypt_input_name := flag.String("din", "encryptedfile", "Add a decrypt input file name without a path, just the name !")
	decrypt_output_name := flag.String("don", "decryptedfile", "Add a decrypt output file name without a path, just the name !")

	useColor := flag.Bool("color", false, "Display colorized output")
	verbose := flag.Bool("v", false, "Verbose flag")
	
	flag.Parse()


	// Environment Variable Check
	if *mode == "vault" {
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
	}

	// Arguments Check
	args_status := functions.CheckArgs()
	switch {
	case *mode != "vault" && *mode != "local":
		functions.Error("arg", "The mode parameter should be vault or local", *useColor, "1")

	case args_status["c"] == true && args_status["d"] == true:
		functions.Error("arg", "\nYou cannot crypt and decrypt at the same time !\nPlease remove either -c ou -d", *useColor, "1")

	case *mode == "vault" && args_status["c"] == false && args_status["d"] == false && args_status["i"] == false && args_status["lookup"] == false:
		functions.Error("arg", "\nThe available actions in vault mode are init, lookup, crypt or decrypt, please specify one.", *useColor, "1")

	case *mode == "local" && args_status["c"] == false && args_status["d"] == false:
		functions.Error("arg", "\nThe available actions in local mode are crypt or decrypt, please specify one.", *useColor, "1")

	case *login_method != "token" && *login_method != "userpass" && *login_method != "approle":
		functions.Error("arg", "\nError: This auth method is not supported, the one supported are: token, userpass, approle", *useColor, "1")

	case args_status["i"] == true && (args_status["sk"] == true || args_status["sv"] == true || args_status["cin"] == true || args_status["con"] == true || args_status["din"] == true || args_status["don"] == true):
		functions.Error("arg", "\nThe only options available for -i are -pk -pt -kt !", *useColor, "1")
	
	case args_status["c"] == true && args_status["din"] == true && args_status["don"] == true:
		functions.Error("arg", "\nThe -din and -don arguments is not available for -c !", *useColor, "1")
	
	case args_status["d"] == true && args_status["cin"] == true && args_status["con"] == true:
		functions.Error("arg", "\nThe -cin and -con arguments are not available for -d !", *useColor, "1")

	case args_status["d"] == true && args_status["din"] == false && *mode == "vault":
		functions.Error("arg", "Must specify input filename with -din !", *useColor, "1")
	
	case args_status["sv"] == true && args_status["sk"] == false:
		functions.Error("arg", "\nIf the secret version (-sv) is specified, you must add the parameter -sk !", *useColor, "1")
	
	}

	if *verbose {
		functions.Debug("##############################################", *useColor)
		functions.Debug("#           Vault-crypter Execution          #", *useColor)
		functions.Debug("##############################################", *useColor)
		functions.Debug("Starting process...", *useColor)
	}

	// Main
	switch {

	// Vault Mode Handling
	case *mode == "vault":

		if *verbose {functions.Debug("Entering Vault Mode.", *useColor)}

		// Initialize the session with Vault and the token generation
		token, _:= functions.InitVault(*login_method, *useColor)

		if *verbose {functions.Debug("Initializing Vault Session and grabing the token.", *useColor)}

		switch {

		// Initialize the transit engine, the transit key and the KV path
		case *init == true:

			if *verbose {functions.Debug("Creating Vault environment.", *useColor)}
			
			functions.EnableTransit(*path_transit, *useColor)
			if *verbose {functions.Debug("Transit Engine created.", *useColor)}

			functions.CreateKeyTransit(*path_transit, *key_name_transit, *useColor)
			if *verbose {functions.Debug("Transit Key created.", *useColor)}

			functions.EnableKV(*path_kv, *useColor)
			if *verbose {functions.Debug("KV Engine created. Initialization done.", *useColor)}

		case *lookup == true:
			if *verbose {functions.Debug("Looking up Vault Token informations...", *useColor)}
			functions.LookupToken(token, *useColor)

		// Handle the encryption mechanism
		case *crypt == true:

			if *verbose {functions.Debug("Grabbing encryption key from Vault.", *useColor)}
			wrapped_key, key_exist, data_key := functions.CheckKey(*mode, *secret_name_version, *secret_name_kv, *path_kv, *path_transit, *key_name_transit, *useColor)

			// Unwrap the wrapped derived key
			plaintext_key := functions.DecryptString(*path_transit, wrapped_key, *key_name_transit, *useColor)
			
			// Decode the derived key
			functions.Key = functions.DecodeBase64([]byte(plaintext_key.Data["plaintext"].(string)), *useColor)
			
			if key_exist == false {
				// Save the wrapped derived key in the kv engine
				// To be tested: data_key.Data["ciphertext"].(string) can may be replaced by wrapped_key - Should be the same result...
				key_version = functions.WriteSecret("kv2", *path_kv+"/data/"+*secret_name_kv, data_key.Data["ciphertext"].(string), *useColor)
			} else {
				key_version = strconv.Itoa(*secret_name_version)
			}
			
			// Crypt the file
			if *verbose {functions.Debug("Encrypting...", *useColor)}
			functions.EncryptFile(*path+*crypt_input_name, *path+"v"+key_version+":"+*crypt_output_name, *useColor)
			if *verbose {
				functions.Debug("Encrypted file available here: "+*crypt_output_name, *useColor)
				functions.Debug("Encryption done.", *useColor)
			}

		// Handle the decryption mechanism
		case *decrypt == true:
			
			if *verbose {functions.Debug("Grabbing decryption key from Vault.", *useColor)}
			wrapped_key = functions.ReadSecret(*path_kv, *secret_name_kv, *secret_name_version, "kv2", *useColor)
			
			// Unwrap the wrapped derived key
			plaintext_key := functions.DecryptString(*path_transit, wrapped_key, *key_name_transit, *useColor)
			
			// Decode the derived key
			functions.Key = functions.DecodeBase64([]byte(plaintext_key.Data["plaintext"].(string)), *useColor)

			// Decrypt the file
			if *verbose {functions.Debug("Decrypting...", *useColor)}
			functions.DecryptFile(*path+*decrypt_input_name, *path+*decrypt_output_name, *useColor)
			if *verbose {
				functions.Debug("Decrypted file available here: decryptedfile. File was created with permissions 0777.", *useColor)
				functions.Debug("Decryption done.", *useColor)
			}
		}

	// Local Mode Handling
	case *mode == "local":
		if *verbose {functions.Debug("Entering Local Mode.", *useColor)}

		switch {

		case *crypt == true:
			if *verbose {functions.Debug("Grabbing local encryption key.", *useColor)}
			functions.CheckKey(*mode, *secret_name_version, *secret_name_kv, *path_kv, *path_transit, *key_name_transit, *useColor)

			if *verbose {functions.Debug("Encrypting...", *useColor)}
			functions.EncryptFile(*path+*crypt_input_name, *path+*crypt_output_name, *useColor)
			if *verbose {
				functions.Debug("Encrypted file available here: "+*crypt_output_name, *useColor)
				functions.Debug("Encryption done.", *useColor)
			}

		case *decrypt == true:
			if *verbose {functions.Debug("Grabbing local decryption key.", *useColor)}
			functions.CheckKey(*mode, *secret_name_version, *secret_name_kv, *path_kv, *path_transit, *key_name_transit, *useColor)

			if *verbose {functions.Debug("Decrypting...", *useColor)}
			functions.DecryptFile(*path+*decrypt_input_name, *path+*decrypt_output_name, *useColor)
			if *verbose {
				functions.Debug("Decrypted file available here: "+*decrypt_output_name+". File was created with permissions 0777.", *useColor)
				functions.Debug("Decryption done.", *useColor)
			}
		}
	}
}

