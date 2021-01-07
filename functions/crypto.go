package functions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/ioutil"
)

var Key []byte

// TO BE DELETED
/*func CheckLocalKey() {
	thekey, err := ioutil.ReadFile("key") //Check to see if a key was already created
	fmt.Printf("Before conversion Key: %x\n", thekey)
        if err != nil {
                Key = createPrivKey() //If not, create one
        } else {
                //key = thekey //If so, set key as the key found in the file
        		Key = DecodeBase64(thekey)
        }
}*/

func EncryptFile(inputfile string, outputfile string, useColor bool) {
	b, err := ioutil.ReadFile(inputfile) //Read the target file
	if err != nil {
		Error("main", "\nUnable to open/read the input file!", useColor, "1")
	}
	ciphertext := encrypt(Key, b, useColor)
	//fmt.Printf("%x\n", ciphertext)
	err = ioutil.WriteFile(outputfile, ciphertext, 0644)
	if err != nil {
		Error("main", "\nUnable to create encrypted file!", useColor, "1")
	}
}

func encrypt(key, text []byte, useColor bool) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		Error("main", "\n"+err.Error(), useColor, "1")
	}
	b := encodeBase64(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		Error("main", "\n"+err.Error(), useColor, "1")
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], b)
	return ciphertext
}

func DecryptFile(inputfile string, outputfile string, useColor bool) {
	z, err := ioutil.ReadFile(inputfile)
	if err != nil {
		Error("main", "\nUnable to open/read encrypted file!", useColor, "1")
	}
	result := decrypt(Key, z, useColor)
	//fmt.Printf("Decrypted: %s\n", result)
	//fmt.Printf("Decrypted file was created with file permissions 0777\n")
	err = ioutil.WriteFile(outputfile, result, 0777)
	if err != nil {
		Error("main", "\nUnable to create decrypted file!", useColor, "1")
	}
}

func decrypt(key, text []byte, useColor bool) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		Error("main", "\n"+err.Error(), useColor, "1")
	}
	if len(text) < aes.BlockSize {
		Error("main", "\nDecrypt Data Error: Invalid length. Verify that your encrypted file is not empty", useColor, "1")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return DecodeBase64(text, useColor)
}

func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func DecodeBase64(b []byte, useColor bool) []byte {
	data, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		Error("main", "\nBad Key !", useColor, "1")
	}
	return data
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

func CreatePrivKey(useColor bool) []byte {
	newkey := []byte(rand_str(32))
	err := ioutil.WriteFile("key", newkey, 0644)
	if err != nil {
		Error("main", "\nError creating Key file!", useColor, "1")
	}
	return newkey
}
