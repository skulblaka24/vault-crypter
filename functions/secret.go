package functions

import (
	"fmt"
	"strconv"
	"io/ioutil"
	"github.com/hashicorp/vault/api"
)

func CheckKey(mode string, secret_name_version int, secret_name_kv string, path_kv string, path_transit string, key_name_transit string, useColor bool) (string, bool, *api.Secret) {
    var key_exist bool
    var data_key *api.Secret
    var wrapped_key string

    if mode == "local" {
		// Check to see if a key was already created
		thekey, err := ioutil.ReadFile("key") 

        if err != nil {
                //If no key, create one
                Key = CreatePrivKey(useColor)
        } else {
                //If one, set key as the key found in the file
        	Key = DecodeBase64(thekey, useColor)
        }
    } else if mode == "vault" {
    	
    	if secret_name_version != 0 {
			wrapped_key = ReadSecret(path_kv, secret_name_kv, secret_name_version, "kv2", useColor)
			key_exist = true

		} else {

			// Get Wrapped Derived Key from the transit engine
			data_key = GetDataKey(path_transit, key_name_transit, useColor)
			wrapped_key = fmt.Sprintf("%v", data_key.Data["ciphertext"])
			key_exist = false

		}
    }
    return wrapped_key, key_exist, data_key
}

func ReadSecret(path string, secret string, version int, kversion string, useColor bool) string {
	var wrapped_key string

	// KV Version 1
	if kversion == "kv1" {

		request, err := vault_client.Logical().Read(path+"/"+secret)
		if err != nil {
			Error("main", "\n"+err.Error(), useColor, "1")
		}

		// Output the value from the token key
		wrapped_key = fmt.Sprintf("%v", request.Data["key"])

	// KV Version 2
	} else if kversion == "kv2" {
		
		s_version := strconv.Itoa(version)

		options := make(map[string][]string)
		options["version"] = []string{s_version}
		
		request, err := vault_client.Logical().ReadWithData(path+"/data/"+secret, options)
		if err != nil {
			// If the path or version is incorrect, the program will panic before printing the error.
			Error("main", "\n"+err.Error(), useColor, "1")
		}

		// Convert the output to a map interface.
		data := request.Data["data"].(map[string]interface{})

		// Output the value from the token key
		wrapped_key = fmt.Sprintf("%v", data["key"])

	}

	return wrapped_key
}

func GetDataKey(path string, key string, useColor bool) (*api.Secret){

	context := map[string]interface{}{
		"context": "Ym9uam91cg==",
	}

	// Can also be transit/datakey/wrapped/
	datakey, err := vault_client.Logical().Write(path + "/datakey/plaintext/" + key, context)
	if err != nil {
		Error("main", "\n"+err.Error(), useColor, "1")
	}
	
	return datakey
}

func DecryptString(path string, ciphertext interface {}, key string, useColor bool) (*api.Secret) {

	decrypted_contents, err := vault_client.Logical().Write(path + "/decrypt/" + key, map[string]interface{} {
		"ciphertext": ciphertext,
		"context": "Ym9uam91cg==",
	})
	if err != nil {
		Error("main", "\nError decrypting file:"+err.Error(), useColor, "1")
	}
	
	return decrypted_contents
}

func WriteSecret(kversion string, path string, key string, useColor bool) string {

	// Version 1
	if kversion == "kv1" {
		options := map[string]interface{}{
				"key":key,
		}

		_, err := vault_client.Logical().Write(path, options)
		if err != nil {
			Error("main", "\n"+err.Error(), useColor, "1")
		}
		return "1"

	// Version 2
	} else if kversion == "kv2" {
		options := map[string]interface{}{
			"data": map[string]interface{}{
				"key":key,
			},
		}

		output, err := vault_client.Logical().Write(path, options)
		if err != nil {
			Error("main", "\n"+err.Error(), useColor, "1")
		}
		kv_version := fmt.Sprintf("%v", output.Data["version"])
		if kv_version == "4294967285" {
			Error("main", "\nError: The KV Engine will start deleting older versions as you've reach the maximum!\nYou have ten key version left, please consider changing the kv path"+err.Error(), useColor, "1")
		}
		
		return kv_version
	}
	return "1"

}
