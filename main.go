package main

import (
	"bufio"
	"crypto/rand"
	b64 "encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"code.cloudfoundry.org/bytefmt"
	"github.com/fatih/color"
	"github.com/slavikmanukyan/idea-go"
)

const BlockSize = 8

// Create SprintXxx functions to mix strings with other non-colorized strings:
var green = color.New(color.FgGreen).SprintFunc()
var blue = color.New(color.FgBlue).SprintFunc()
var red = color.New(color.FgRed).SprintFunc()

func handleError(err error) {
	fmt.Printf("%v", red(err))
	os.Exit(2)
}

func generateKey(keySize *int, saveKey *string) {
	key := make([]uint8, *keySize)
	_, err := rand.Read(key)
	if err != nil {
		handleError(err)
		return
	}

	absPath, err := filepath.Abs(*saveKey)
	if err != nil {
		handleError(err)
		return
	}
	f, err := os.Create(absPath)
	if err != nil {
		handleError(err)
		return
	}
	defer f.Close()

	f.WriteString("----Idea Key Start----\n")
	f.WriteString(b64.StdEncoding.EncodeToString(key))
	f.WriteString("\n----Idea Key End----")
	f.Sync()

	fmt.Printf("Random key generated in file %s ...\n", absPath)
}

func parseKey(keySize *int, keyPath *string) []uint8 {
	absPath, err := filepath.Abs(*keyPath)
	if err != nil {
		handleError(err)
		return nil
	}
	f, err := os.Open(absPath)
	if err != nil {
		handleError(err)
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	var key []uint8
	for i := 0; i < 4; i++ {
		notEnd := scanner.Scan()
		if (!notEnd && i != 3) || (notEnd && i == 3) {
			handleError(errors.New("Wrong signature"))
			return nil
		}
		if i == 3 {
			break
		}
		line := scanner.Text()
		if i == 0 && line != "----Idea Key Start----" ||
			i == 2 && line != "----Idea Key End----" {
			handleError(errors.New("Wrong signature"))
			return nil
		}
		if i == 1 {
			key, err = b64.StdEncoding.DecodeString(line)
			return key
		}
		if err != nil {
			handleError(err)
			return nil
		}
	}

	return nil
}

func paddData(data []uint8) []uint8 {
	if len(data)%BlockSize == 0 {
		ret := make([]uint8, len(data))
		copy(ret, data)
		for i := 0; i < BlockSize; i++ {
			ret = append(ret, BlockSize)
		}
		return ret
	} else if len(data)%BlockSize == BlockSize-1 {
		ret := make([]uint8, len(data))
		copy(ret, data)
		for i := 0; i <= BlockSize; i++ {
			ret = append(ret, 1)
		}
		return ret
	} else {
		ret := make([]uint8, len(data))
		copy(ret, data)
		for i := 0; i < BlockSize-len(data)%BlockSize; i++ {
			ret = append(ret, uint8(BlockSize-len(data)%BlockSize))
		}
		return ret
	}
}

func dePaddData(data []uint8) []uint8 {
	if data[len(data)-1] == BlockSize {
		ret := make([]uint8, len(data)-BlockSize)
		copy(ret, data[0:len(data)-BlockSize])
		return ret
	} else if data[len(data)-1] == 1 {
		ret := make([]uint8, len(data)-BlockSize-1)
		copy(ret, data[0:len(data)-BlockSize-1])
		return ret
	} else {
		ret := make([]uint8, len(data)-int(data[len(data)-1]))
		copy(ret, data[0:len(data)-int(data[len(data)-1])])
		return ret
	}
}

func decrypt(data []uint8, key []uint8) []uint8 {
	cipher := idea.NewBlock(key)
	if len(data)%BlockSize != 0 {
		handleError(errors.New("Wrond data provided to decrypt!"))
		return nil
	}
	blockCount := len(data) / BlockSize

	var decData []uint8
	for i := 0; i < blockCount; i++ {
		decData = append(decData, cipher.Decrypt(data[i*BlockSize:(i+1)*BlockSize])...)
	}
	return dePaddData(decData)
}

func encrypt(data []uint8, key []uint8) []uint8 {
	cipher := idea.NewBlock(key)

	data = paddData(data)
	blockCount := len(data) / BlockSize

	var encData []uint8
	for i := 0; i < blockCount; i++ {
		encData = append(encData, cipher.Crypt(data[i*BlockSize:(i+1)*BlockSize])...)
	}
	return encData
}

func main() {
	stringInput := flag.String("text", "", "Text to encrypt or decrypt")
	filePath := flag.String("file", "", "A file to encrypt or decrypt")
	savePath := flag.String("save", "", "File to save data")
	keyPath := flag.String("key", "", "encryption key path")
	saveKey := flag.String("save-key", "", "file to generate random key")
	keySize := flag.Int("key-size", 16, "key size in bytes")
	decrypting := flag.Bool("d", false, "decrypt input")

	flag.Parse()
	if len(*saveKey) > 0 {
		generateKey(keySize, saveKey)
		return
	}

	var key []uint8
	if len(*keyPath) > 0 {
		key = parseKey(keySize, keyPath)
	}

	if len(key) == 0 {
		handleError(errors.New("Need key ..."))
		return
	}

	var result []uint8
	if len(*stringInput) > 0 {
		data := []uint8(*stringInput)
		fmt.Println(key)
		if *decrypting {
			fmt.Printf("Decrypting text: \"%s\"\n", blue(*stringInput))
			result = decrypt(data, key)
			fmt.Printf("Decryption result: \"%s\"\n", green(string(result)))
		} else {
			fmt.Printf("Encrypting text: \"%s\"\n", blue(*stringInput))
			result = encrypt(data, key)
			fmt.Printf("Encryption result: \"%s\"\n", green(string(result)))
		}
	}

	if len(*filePath) > 0 {
		if len(*savePath) == 0 {
			handleError(errors.New("Need save path!"))
			return
		}

		absPath, err := filepath.Abs(*filePath)
		if err != nil {
			handleError(err)
			return
		}
		if err != nil {
			handleError(err)
			return
		}
		data, err := ioutil.ReadFile(absPath)
		if err != nil {
			handleError(err)
			return
		}
		stat, err := os.Stat(absPath)
		if err != nil {
			handleError(err)
			return
		}
		size := stat.Size()
		if *decrypting {
			fmt.Printf("Decrypting file of size %s ...\n", green(bytefmt.ByteSize(uint64(size))))
			result = decrypt(data, key)
		} else {
			fmt.Printf("Encrypting file of size %s ...\n", green(bytefmt.ByteSize(uint64(size))))
			result = encrypt(data, key)
		}
	}

	if *decrypting {
		if len(*savePath) == 0 {
			handleError(errors.New("Need save path!"))
			return
		}
	}

	if len(*savePath) > 0 && len(result) > 0 {
		absPath, err := filepath.Abs(*savePath)
		if err != nil {
			handleError(err)
			return
		}
		err = ioutil.WriteFile(absPath, result, 0644)
		if err != nil {
			handleError(err)
			return
		}

		fmt.Printf("Result saved in %s\n", blue(*savePath))
	}
}
