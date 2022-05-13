package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/kyber/v4/util/random"
)

func read_int32(data []byte) int32 {
	return int32(uint32(data[0]) + uint32(data[1])<<8 + uint32(data[2])<<16 + uint32(data[3])<<24)
}

const (
	SERVER_HOST = "localhost"
	SERVER_PORT = "9988"
	SERVER_TYPE = "tcp"
)

var rng = random.New()

//generate Random Ascii
func GenerateRandomASCIIString(length int) (string, error) {
	result := ""
	for {
		if len(result) >= length {
			return result, nil
		}
		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		if err != nil {
			return "", err
		}
		n := num.Int64()
		// Make sure that the number/byte/letter is inside
		// the range of printable ASCII characters (excluding space and DEL)
		if n > 32 && n < 127 {
			result += string(n)
		}
	}
}
func main() {
	fmt.Println("Server Running...")
	server, err := net.Listen(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	defer server.Close()
	fmt.Println("Listening on " + SERVER_HOST + ":" + SERVER_PORT)
	fmt.Println("Waiting for client...")
	for {
		connection, err := server.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		fmt.Println("client connected")
		go processClient(connection)
	}
}
func processClient(connection net.Conn) {

	//---------------------------------WORK-FIATSHAMIR-------------------------------------
	suite := suites.MustFind("Ed25519")
	length := 10

	//generate ascii
	m, err := GenerateRandomASCIIString(length)
	if err != nil {
		panic(err)
	}

	argCount := len(os.Args[1:])

	if argCount > 0 {
		m = string(os.Args[1])
	}

	//Message go byte
	message := []byte(m)

	//hash
	scal := sha256.Sum256(message[:])

	x := suite.Scalar().SetBytes(scal[:32])

	//pick RNG point G and Send G to Alice
	G := suite.Point().Pick(rng)
	G_by, err := G.MarshalBinary()
	fmt.Println("G", len(G_by))
	_, err = connection.Write(G_by)
	time.Sleep(1 * time.Millisecond)

	//pick RNG point H and Send H to Alice
	H := suite.Point().Pick(rng)
	H_by, err := H.MarshalBinary()
	fmt.Println("H", len(H_by))
	_, err = connection.Write(H_by)
	time.Sleep(1 * time.Millisecond)

	//mul x ang G and Send xG to Alice
	xG := suite.Point().Mul(x, G)
	xG_by, err := xG.MarshalBinary()
	fmt.Println("xG", len(xG_by))
	_, err = connection.Write(xG_by)
	time.Sleep(1 * time.Millisecond)

	//mul x ang H and Send xH to Alice
	xH := suite.Point().Mul(x, H)
	xH_by, err := xH.MarshalBinary()
	fmt.Println("xH", len(xH_by))
	_, err = connection.Write(xH_by)
	time.Sleep(1 * time.Millisecond)

	//Read a Rand C from Alice
	var c kyber.Scalar
	buf := make([]byte, 1024)
	mLen, err := connection.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	if err := suite.Read(bytes.NewBuffer(buf[:mLen]), &c); err != nil {
		log.Fatal("...", err.Error())
	}

	//pick rand V
	v := suite.Scalar().Pick(suite.RandomStream())
	//Mul v and G
	vG := suite.Point().Mul(v, G)
	//Send Vg to Alice
	vG_by, err := vG.MarshalBinary()
	fmt.Println("vG", len(vG_by))
	_, err = connection.Write(vG_by)
	time.Sleep(1 * time.Millisecond)

	//mul v and H
	vH := suite.Point().Mul(v, H)
	//Send Vh to Alice
	vH_by, err := vH.MarshalBinary()
	fmt.Println("vH", len(vH_by))
	_, err = connection.Write(vH_by)
	time.Sleep(1 * time.Millisecond)

	//mul (x and c) -> r , and then sub (v and r) -> r
	r := suite.Scalar()
	r.Mul(x, c).Sub(v, r)

	r_by, err := r.MarshalBinary()
	fmt.Println("r", len(r_by))
	//send r to Alice
	_, err = connection.Write(r_by)

	//mul r and G
	rG := suite.Point().Mul(r, G)
	////mul r and H
	rH := suite.Point().Mul(r, H)

	//mul cand xG
	cxG := suite.Point().Mul(c, xG)
	//mul cand xH
	cxH := suite.Point().Mul(c, xH)

	//add rG and cXG
	a := suite.Point().Add(rG, cxG)
	//add rH and cXH
	b := suite.Point().Add(rH, cxH)

	//--------------------------------------------------------------------------------

	fmt.Printf("Bob and Alice agree:\n G:\t%s\n H:\t%s\n\n", G, H)
	fmt.Printf("Bob's Password\t: %s\n", m)
	fmt.Printf("Bob's Secret (x): %s\n\n", x)
	fmt.Printf("Bob sends these values:\n xG:\t%s\n xH: \t%s\n\n", xG, xH)
	fmt.Printf("Alice sends challenge:\n c: \t%s\n\n", c)
	fmt.Printf("Bob computes:\n v:\t%s\n r:\t%s\n\n", v, r)

	//Conditon for Verification a and b
	if !(vG.Equal(a) && vH.Equal(b)) {
		fmt.Println("Verifikasi Gagal!")
	} else {
		fmt.Println("Verifikasi Berhasil")
	}
	fmt.Println("Closing")
	connection.Close()
}
