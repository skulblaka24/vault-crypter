package functions

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"github.com/hashicorp/vault/api" // go get github.com/hashicorp/vault/api
)

func CheckKey(mode string, secret_name_version int, secret_name_kv string, path_kv string, path_transit string, key_name_transit string) (string, bool, *api.Secret) {
	var key_exist bool
    var data_key *api.Secret
    var wrapped_key string

	if mode == "local" {
		thekey, err := ioutil.ReadFile("key") //Check to see if a key was already created
		//fmt.Printf("Before conversion Key: %x\n", thekey)
        if err != nil {
                Key = CreatePrivKey() //If not, create one
        } else {
                //key = thekey //If so, set key as the key found in the file
        		Key = DecodeBase64(thekey)
        }
    } else if mode == "vault" {
    	
    	if secret_name_version != 0 {
			wrapped_key = ReadSecret(path_kv, secret_name_kv, secret_name_version, "kv2")
			key_exist = true

			// Debug
			//if *debug {fmt.Printf("WRAPPED_KEY: %v | %T\n", wrapped_key, wrapped_key)}
		} else {

			// Get Wrapped Derived Key from the transit engine
			data_key = GetDataKey(path_transit, key_name_transit)
			wrapped_key = fmt.Sprintf("%v", data_key.Data["ciphertext"])
			key_exist = false

			// Debug
			//if *debug {fmt.Printf("DATA_KEY: %v | %T\n\n", data_key, data_key)
			//fmt.Printf("WRAPPED_KEY: %v | %T\n", wrapped_key, wrapped_key)}
		}
    }
    return wrapped_key, key_exist, data_key
}

func ReadSecret(path string, secret string, version int, kversion string) string {
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

func GetDataKey(path string, key string) (*api.Secret){

	context := map[string]interface{}{
		"context": "Ym9uam91cg==",
	}

	// Can also be transit/datakey/wrapped/
	datakey, err := vault_client.Logical().Write(path + "/datakey/plaintext/" + key, context)
	if err != nil {
		fmt.Println(err)
	}

	// Debug
	//fmt.Printf("Wrapped_datakey: %s\n", datakey.Data["ciphertext"])
	//fmt.Printf("Plaintext_datakey: %s\n", datakey.Data["plaintext"])
	
	return datakey
}

func DecryptString(path string, ciphertext interface {}, key string) (*api.Secret) {

	decrypted_contents, err := vault_client.Logical().Write(path + "/decrypt/" + key, map[string]interface{} {
		"ciphertext": ciphertext,
		"context": "Ym9uam91cg==",
	})
	if err != nil {
		fmt.Printf("Error decrypting file: %s", err)
	}
	
	//fmt.Printf("Decrypted: %s\n", decrypted_contents.Data["plaintext"])

	return decrypted_contents
}

func WriteSecret(kversion string, path string, key string) string {

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
