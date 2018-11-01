package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
)

// https://www.codeproject.com/Articles/1172340/Hashcash-or-Proof-of-Work
func main() {
	fmt.Println(Verify("1:20:1303030600:adam@cypherspace.org::McMybZIhxKXu57jd:ckvi"))
}

func Verify(header string) bool {
	zbits, err := strconv.ParseInt(header[2:4], 10, 64)
	if err != nil {
		return false
	}
	bytesToCheck := zbits / 8
	remainderBitsToCheck := zbits % 8
	zArray := bytes.Repeat([]byte{0x00}, int(bytesToCheck))
	remainderMask := 0xFF << uint(8-remainderBitsToCheck)
	sha := sha1.New()
	sha.Write([]byte(header))
	hash := sha.Sum(nil)
	return bytes.Compare(hash[:bytesToCheck], zArray) == 0 && (int(hash[bytesToCheck])&remainderMask) == 0
}

func getCounter() {
	var counter int16
	for {
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.LittleEndian, counter)
		if err != nil {
			log.Fatal(err)
		}
		o := base64.StdEncoding.EncodeToString(buf.Bytes())
		if Verify("1:20:1303030600:adam@cypherspace.org::McMybZIhxKXu57jd:" + o) {
			break
		}
		counter++
	}
	fmt.Println("counter is", counter)
}
