package functions

import (
	
	"fmt"
	"os"
	"flag"
	"time"
	"bufio"
	"strings"
	"strconv"
	"github.com/hashicorp/vault/api" // go get github.com/hashicorp/vault/api
)

var vault_addr = os.Getenv("VAULT_ADDR")
var vault_token string
var vault_client *api.Client // global variable
var color string

// Error Type | Message | Color | Exit type
func Error(error_type string, message string, useColor bool, exit_type string) {
	if useColor == true{color = ColorRed}else{color = ColorWhite}

	fmt.Printf("%v#################################################################%v\n", color, ColorReset)
	if error_type == "arg" {
		fmt.Printf("%v#%v                        Argument Error                         %v#%v\n", color, ColorReset, color, ColorReset)
	} else if error_type == "main" {
		fmt.Printf("%v#%v                        Process Error                          %v#%v\n", color, ColorReset, color, ColorReset)
	} else if error_type == "env" {
		fmt.Printf("%v#%v                 Environment Variable Error                    %v#%v\n", color, ColorReset, color, ColorReset)
	}
	fmt.Printf("%v#################################################################%v\n", color, ColorReset)
	fmt.Printf("%vDate:%v %v\n", color, ColorReset, time.Now().Format("02/01/2006"))
	fmt.Printf("%vTime:%v %v\n", color, ColorReset, time.Now().Format("15:04:05"))
	
	fmt.Printf("%vMessage:%v %v\n", color, ColorReset, message)
	if exit_type == "0" || exit_type == "1" {
		fmt.Printf("Exiting....\n")
		e, _ := strconv.Atoi(exit_type)
		os.Exit(e)
	}
}

/*func Debug(error_type string, message string, Color string, exit_type string) {
	if error_type == "arg" {
		fmt.Printf("#################################################################\n")
		fmt.Printf("#                        Argument Error                         #\n")
		fmt.Printf("#################################################################\n")
		fmt.Printf("Message: %v\n", message)
		if exit_type == "0" || exit_type == "1" {
			fmt.Printf("Exiting....\n")
		}
	}
}*/

func IsArgPassed(name string) bool {
    found := false
    flag.Visit(func(f *flag.Flag) {
        if f.Name == name {
            found = true
        }
    })
    return found
}

func CheckArgs() map[string]bool {
	list := make(map[string]bool)
    flag.VisitAll(func(f *flag.Flag) {
    	list[f.Name] = IsArgPassed(f.Name)
        
        // Debug
        //fmt.Printf("Out: "+f.Name+": %v\n", m[f.Name])
    })
    return list
}

func InitVault(authType string) (string, *api.Client) {
	
	// Config can be set through ENV before any step and creating a new client
    //os.Setenv("VAULT_TOKEN", "<TOKEN>")

	//fmt.Println("### Step: Vault Initialisation:")
	config := &api.Config{
		Address: vault_addr,
	}
	client, err := api.NewClient(config)
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
		
		//fmt.Printf("Token: %s\n", vault_token)

	case authType == "userpass":
		//fmt.Println("authType: userpass")

		vault_username := os.Getenv("VAULT_USERNAME")
		vault_password := os.Getenv("VAULT_PASSWORD")
		
		vault_token = userpassLogin(vault_username, vault_password)

		//fmt.Printf("Token: %s\n", vault_token)
		
	case authType == "approle":
		//fmt.Println("authType: approle")

		vault_role_id := os.Getenv("VAULT_ROLE_ID")
		vault_secret_id := os.Getenv("VAULT_SECRET_ID")

		vault_token = approleLogin(vault_role_id, vault_secret_id)

		//fmt.Printf("Token: %s\n", vault_token)
	}

	vault_client.SetToken(vault_token)
	
	return vault_token, vault_client
}

func EnableTransit (path string) {

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

func EnableKV (path string) {

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

func CreateKeyTransit (path string, key_name string) {

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

