package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
)

var one = big.NewInt(1)

// ErrMessageTooLong is returned when attempting to encrypt a message which is
// too large for the size of the public key.
var ErrMessageTooLong = errors.New("paillier: message too long for Paillier public key size")

// This example demonstrates basic usage of this library.
// Features shown:
//   * Encrypt/Decrypt
//   * Homomorphic cipher text addition
//   * Homomorphic addition with constant
//   * Homomorphic multiplication with constant

var num = flag.String("int", "", "message or integer to encode")
var e1 = flag.String("m1", "", "encrypted integer message 1")
var e2 = flag.String("m2", "", "other encrypted integer number")
var privateKey = flag.String("private", "", "hex encoded private key")
var publicKey = flag.String("public", "", "hex encoded public key")
var keyGen = flag.Bool("generate", false, "Generate a new secret, private key (and public)")
var add = flag.Bool("add", false, "sum up the messages on stdin. One line per message, newline terminated.")
var eMessage = flag.String("m", "", "encrypted, hex encoded string that contains an integer")
var test = flag.Bool("test", false, "this flag will run a test sequence of 7+3=10")
var clients = flag.Int("c", 1, "number of thread clients to run concurrently for summing up encrypted messages")
var verbose = flag.Bool("v", false, "verbose output for debugging")
var done sync.WaitGroup

func main() {
	flag.Parse()
	if *keyGen {

		privKey, err := generateKey(rand.Reader, 128)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Printf("Private L=%x\n", privKey.L)
		fmt.Printf("Public  N=%x\n", privKey.PublicKey.N)
	} else if *privateKey != "" && *publicKey != "" && *num != "" {

		//	privKey, err := loadKey(*privateKey, *publicKey)
		//if err != nil {
		//fmt.Println(err)
		//	return
		//}

		//		fmt.Printf("Private L=%x\n", privKey.L)
		//	fmt.Printf("Public  N=%x\n", privKey.PublicKey.N)
		//Mbytes, err := hex.DecodeString(*signature)
		//msg, err := Decrypt(privKey, Mbytes)
		//checkErr(err)
		//fmt.Printf("Message=%x\n", hex.EncodeToString(msg))
		//	} else if *publicKey != "" && *num != "" {

	} else if *test && *privateKey != "" && *publicKey != "" {
		//decrypt
		key, err := loadKey(*privateKey, *publicKey) //just load the public key
		if err != nil {
			fmt.Println(err)
			return
		}
		// Encrypt the number "15".
		m3 := new(big.Int).SetInt64(3)
		c3, err := Encrypt(&key.PublicKey, m3.Bytes())
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Encryption Result of 3: ", hex.EncodeToString(c3))
		// Decrypt the number "3".
		d, err := Decrypt(key, c3)
		if err != nil {
			fmt.Println(err)
			return
		}
		plainText := new(big.Int).SetBytes(d)
		fmt.Println("Decryption Result of 3: ", plainText.String())

		// Encrypt the number "7".
		m7 := new(big.Int).SetInt64(7)
		c7, err := Encrypt(&key.PublicKey, m7.Bytes())
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Encryption Result of 7: ", hex.EncodeToString(c7))
		// Add the encrypted integers 15 and 20 together.
		plusM3M7 := AddCipher(&key.PublicKey, c3, c7)
		decryptedAddition, err := Decrypt(key, plusM3M7)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Encryption Result of 3+7: ", hex.EncodeToString(plusM3M7))
		fmt.Println("Result of 3+7 after decryption: ",
			new(big.Int).SetBytes(decryptedAddition).String()) // 35

	} else if *publicKey != "" && *add {
		//add encrypted numbers
		key, err := loadKey("", *publicKey) //just load the public key
		if err != nil {
			fmt.Println(err)
			return
		}
		trafficChannel := make(chan string)
		for i := 0; i < *clients; i++ {
			done.Add(1)
			if *verbose {
				println("go client ", i)
			}
			//			go client(trafficChannel, &key.PublicKey, &key, i)
			go client(trafficChannel, *key, i)
		}

		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			trafficChannel <- scanner.Text() //put work into the channel from Stdin
		}
		close(trafficChannel)
		done.Wait()
	} else if *privateKey != "" && *publicKey != "" {
		//decrypt
		key, err := loadKey(*privateKey, *publicKey) //just load the public key
		if err != nil {
			fmt.Println(err)
			return
		}

		trafficChannel := make(chan string)
		for i := 0; i < *clients; i++ {
			done.Add(1)
			if *verbose {
				println("go client ", i)
			}
			//			go client(trafficChannel, &key.PublicKey, &key, i)
			go clientDecrypt(trafficChannel, *key, i)
		}

		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			trafficChannel <- scanner.Text() //put work into the channel from Stdin
		}
		close(trafficChannel)
		done.Wait()
	} else if *publicKey != "" {
		//encrypt numbers
		key, err := loadKey("", *publicKey) //just load the public key
		if err != nil {
			fmt.Println(err)
			return
		}
		trafficChannel := make(chan string)
		for i := 0; i < *clients; i++ {
			done.Add(1)
			if *verbose {
				println("go client ", i)
			}
			//			go client(trafficChannel, &key.PublicKey, &key, i)
			go clientEncryptInt(trafficChannel, *key, i)
		}

		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			trafficChannel <- scanner.Text() //put work into the channel from Stdin
		}
		close(trafficChannel)
		done.Wait()
	}
}

// Integer power: compute a**b using binary powering algorithm
// See Donald Knuth, The Art of Computer Programming, Volume 2, Section 4.6.3
func Pow(a, b int64) int64 {
	var p int64
	p = 1
	for b > 0 {
		if b&1 != 0 {
			p *= a
		}
		b >>= 1
		a *= a
	}
	return p
}

//func client(trafficChannel chan string, publicKey *PublicKey, privateKey *PrivateKey, i int) {
func clientDecrypt(trafficChannel chan string, key PrivateKey, i int) {
	defer done.Done()
	//	var plusBytes []byte
	//var lastAddedBytes []byte
	for line := range trafficChannel {
		//		i, err := strconv.ParseInt(line, 10, 64)
		//	if err != nil {
		//	checkErr(err)
		//}

		/////////////////
		eBytes, err := hex.DecodeString(line)
		checkErr(err)
		decrypted, err := Decrypt(&key, eBytes)
		checkErr(err)
		fmt.Printf("%s\n", new(big.Int).SetBytes(decrypted).String())
	}
	//	decryptedAddition, err := Decrypt(&key, plusBytes)
	//checkErr(err)
	//	fmt.Printf("output1[%d]=%d\n", i, decryptedAddition)
	//fmt.Printf("output2[%d]=%x\n", i, plusBytes)
}

func clientEncryptInt(trafficChannel chan string, key PrivateKey, i int) {
	defer done.Done()
	for line := range trafficChannel {
		arr := strings.Split(line, ",") //Delimeter for multiple value inputs to stdin. will be encoded in base 3 billion (3E6, 3E12) for 3 values and base 3 quintillion (3E9) for 2 values

		bi := new(big.Int)
		p := new(big.Int)
		bi0 := new(big.Int)
		bi1 := new(big.Int)
		bi2 := new(big.Int)
		/*
			if len(arr) == 2 {
				//arr0, err := strconv.ParseInt(arr[0], 10, 64)
				//		checkErr(err)
				//			arr1, err := strconv.ParseInt(arr[1], 10, 64)
				//	checkErr(err)
				bi0.SetString(arr[0], 10) // decimal
				bi1.SetString(arr[1], 10) // decimal
				p.Mul(bi0, 1000000000)    //			i = arr0*Pow(10, 9) + arr1 //this will move the second number (arr1) into the most significant half of i
				bi.Add(p, bi1)            //this will move the second number (arr1) into the most significant half of i

			} else if len(arr) == 3 {
				arr0, err := strconv.ParseInt(arr[0], 10, 64)
				checkErr(err)
				arr1, err := strconv.ParseInt(arr[1], 10, 64)
				checkErr(err)
				arr2, err := strconv.ParseInt(arr[2], 10, 64)
				checkErr(err)
				i = arr0*Pow(10, 12) + arr1*Pow(10, 6) + arr2 //this will move the second number (arr1) into the most significant half of i

			} else {
				//			var err error
				//		i, err = strconv.ParseInt(line, 10, 64)
				//	if err != nil {
				//	checkErr(err)
				//}
		*/
		bi0.SetString(arr[0], 10) // decimal
		//	}
		if *verbose {
			println("bi=", bi)
		}
		//		m := new(big.Int).SetInt64(i)
		c, err := Encrypt(&key.PublicKey, bi0.Bytes())
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("%x\n", c)
	}
}

func client(trafficChannel chan string, key PrivateKey, i int) {
	defer done.Done()
	var plusBytes []byte
	var lastAddedBytes []byte
	for line := range trafficChannel {
		eBytes, err := hex.DecodeString(line)
		checkErr(err)

		if lastAddedBytes != nil {
			//			plusBytes = AddCipher(Key, eBytes, lastAddedBytes) // only
			plusBytes = AddCipher(&key.PublicKey, eBytes, lastAddedBytes) // only
			//plusBytes = AddCipher(&key.PublicKey, c7, c7) // only
		}
		if plusBytes != nil {
			lastAddedBytes = plusBytes
		} else {
			lastAddedBytes = eBytes
			plusBytes = eBytes
		}
	}
	fmt.Printf("%x\n", plusBytes)
}
func loadKey(Lhex string, Nhex string) (*PrivateKey, error) {
	// GenerateKey generates an Paillier keypair of the given bit size using the
	// random source random (for example, crypto/rand.Reader).

	Lbytes, err := hex.DecodeString(Lhex)
	if err != nil {
		return nil, err
	}
	Nbytes, err := hex.DecodeString(Nhex)
	if err != nil {
		return nil, err
	}
	l := new(big.Int).SetBytes(Lbytes)
	n := new(big.Int).SetBytes(Nbytes)

	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        new(big.Int).Add(n, one), // g = n + 1
		},
		L: l,
		U: new(big.Int).ModInverse(l, n),
	}, nil
}

func generateKey(random io.Reader, bits int) (*PrivateKey, error) {
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// n = p * q
	n := new(big.Int).Mul(p, q)

	// l = phi(n) = (p-1) * q(-1)
	l := new(big.Int).Mul(
		new(big.Int).Sub(p, one),
		new(big.Int).Sub(q, one),
	)

	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        new(big.Int).Add(n, one), // g = n + 1
		},
		L: l,
		U: new(big.Int).ModInverse(l, n),
	}, nil
}

// PrivateKey represents a Paillier key.
type PrivateKey struct {
	PublicKey
	L *big.Int // phi(n), (p-1)*(q-1)
	U *big.Int // l^-1 mod n
}

// PublicKey represents the public part of a Paillier key.
type PublicKey struct {
	N        *big.Int // modulus
	G        *big.Int // n+1, since p and q are same length
	NSquared *big.Int
}

// Encrypt encrypts a plain text represented as a byte array. The passed plain
// text MUST NOT be larger than the modulus of the passed public key.
func Encrypt(pubKey *PublicKey, plainText []byte) ([]byte, error) {
	r, err := rand.Prime(rand.Reader, pubKey.N.BitLen())
	if err != nil {
		return nil, err
	}

	m := new(big.Int).SetBytes(plainText)
	if pubKey.N.Cmp(m) < 1 { // N < m
		return nil, ErrMessageTooLong
	}

	// c = g^m * r^n mod n^2
	n := pubKey.N
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(pubKey.G, m, pubKey.NSquared),
			//new(big.Int).Mod(new(big.Int).Add(one, new(big.Int).Mul(m, n)), pubKey.NSquared), //performance optimization
			new(big.Int).Exp(r, n, pubKey.NSquared),
		),
		pubKey.NSquared,
	)

	return c.Bytes(), nil
}

// Decrypt decrypts the passed cipher text.
func Decrypt(privKey *PrivateKey, cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)

	if privKey.NSquared.Cmp(c) < 1 { // c < n^2
		return nil, ErrMessageTooLong
	}

	// c^l mod n^2
	a := new(big.Int).Exp(c, privKey.L, privKey.NSquared)

	// L(a)
	// (a - 1) / n
	l := new(big.Int).Div(
		new(big.Int).Sub(a, one),
		privKey.N,
	)

	// m = L(c^l mod n^2) * u mod n
	m := new(big.Int).Mod(
		new(big.Int).Mul(l, privKey.U),
		privKey.N,
	)

	return m.Bytes(), nil
}

// AddCipher homomorphically adds together two cipher texts.
// To do this we multiply the two cipher texts, upon decryption, the resulting
// plain text will be the sum of the corresponding plain texts.
func AddCipher(pubKey *PublicKey, cipher1, cipher2 []byte) []byte {
	x := new(big.Int).SetBytes(cipher1)
	y := new(big.Int).SetBytes(cipher2)

	// x * y mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(x, y),
		pubKey.NSquared,
	).Bytes()
}

// Add homomorphically adds a passed constant to the encrypted integer
// (our cipher text). We do this by multiplying the constant with our
// ciphertext. Upon decryption, the resulting plain text will be the sum of
// the plaintext integer and the constant.
func Add(pubKey *PublicKey, cipher, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c * g ^ x mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(c, new(big.Int).Exp(pubKey.G, x, pubKey.NSquared)),
		pubKey.NSquared,
	).Bytes()
}

// Mul homomorphically multiplies an encrypted integer (cipher text) by a
// constant. We do this by raising our cipher text to the power of the passed
// constant. Upon decryption, the resulting plain text will be the product of
// the plaintext integer and the constant.
func Mul(pubKey *PublicKey, cipher []byte, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c ^ x mod n^2
	return new(big.Int).Exp(c, x, pubKey.NSquared).Bytes()
}

// MyCaller returns the caller of the function that called it :)
func myCaller() string {

	// we get the callers as uintptrs - but we just need 1
	fpcs := make([]uintptr, 1)

	// skip 3 levels to get to the caller of whoever called Caller()
	n := runtime.Callers(3, fpcs)
	if n == 0 {
		return "n/a" // proper error her would be better
	}

	// get the info of the actual function that's in the pointer
	fun := runtime.FuncForPC(fpcs[0] - 1)
	if fun == nil {
		return "n/a"
	}

	// return its name
	return fun.Name()
}
func checkErr(err error) {
	if err != nil {
		println("Error=", err)
		println(myCaller())
	}
}
