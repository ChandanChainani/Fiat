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

func GenerateRandomASCIIString(length int) (string, error) {
	result := ""
	for {
		if len(result) >= length {
			// fmt.Println(result)
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
	fmt.Println("Exiting")
}
func processClient(connection net.Conn) {
	fmt.Println("processClient")

	//---------------------------------WORK-FIATSHAMIR-------------------------------------
	suite := suites.MustFind("Ed25519")
	length := 10

	m, err := GenerateRandomASCIIString(length)
	if err != nil {
		panic(err)
	}

	argCount := len(os.Args[1:])

	if argCount > 0 {
		m = string(os.Args[1])
	}

	message := []byte(m)
	scal := sha256.Sum256(message[:])

	x := suite.Scalar().SetBytes(scal[:32])

	G := suite.Point().Pick(rng)
	// G_by, err := G.MarshalBinary()
  G_by := bytes.Buffer{}
  suite.Write(&G_by, &G)
	_, err = connection.Write(G_by.Bytes())
	/// fmt.Println(err)
	// defer connection.Close()

	H := suite.Point().Pick(rng)
	// H_by, err := H.MarshalBinary()
  H_by := bytes.Buffer{}
  suite.Write(&H_by, &H)
	_, err = connection.Write(H_by.Bytes())
	/// fmt.Println(err)
	// defer connection.Close()

	xG := suite.Point().Mul(x, G)
	// xG_by, err := xG.MarshalBinary()
  xG_by := bytes.Buffer{}
  suite.Write(&xG_by, &xG)
	_, err = connection.Write(xG_by.Bytes())
	/// fmt.Println(err)
	// defer connection.Close()

	xH := suite.Point().Mul(x, H)
	// xH_by, err := xH.MarshalBinary()
  xH_by := bytes.Buffer{}
  suite.Write(&xH_by, &xH)
	_, err = connection.Write(xH_by.Bytes())
	// fmt.Println(err)

	var c kyber.Scalar
	// buf := bytes.Buffer{}
	buf := make([]byte, 1024)
	mLen, err := connection.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	if err := suite.Read(bytes.NewBuffer(buf[:mLen]), &c); err != nil {
		log.Fatal("...", err.Error())
	}

	v := suite.Scalar().Pick(suite.RandomStream())
	vG := suite.Point().Mul(v, G)
	// vG_by, err := vG.MarshalBinary()
  vG_by := bytes.Buffer{}
  suite.Write(&vG_by, &vG)
	_, err = connection.Write(vG_by.Bytes())
	// defer connection.Close()

	vH := suite.Point().Mul(v, H)
	// vH_by, err := vH.MarshalBinary()
  vH_by := bytes.Buffer{}
  suite.Write(&vH_by, &vH)
	_, err = connection.Write(vH_by.Bytes())
	// defer connection.Close()

	r := suite.Scalar()
	r.Mul(x, c).Sub(v, r)
	// fmt.Println("v", v)
	// fmt.Println("x", x)
	// fmt.Println("c", c)
	// fmt.Println("r", r)

	// r_by, err := r.MarshalBinary()
  r_by := bytes.Buffer{}
  suite.Write(&r_by, &r)
  // fmt.Println(r_by)

  // byteBuf := bytes.Buffer{}
	// suite.Write(&byteBuf, &r)

	_, err = connection.Write(r_by.Bytes())
	// defer connection.Close()

	rG := suite.Point().Mul(r, G)
	rH := suite.Point().Mul(r, H)

	cxG := suite.Point().Mul(c, xG)
	cxH := suite.Point().Mul(c, xH)

	a := suite.Point().Add(rG, cxG)
	b := suite.Point().Add(rH, cxH)

	//--------------------------------------------------------------------------------

	fmt.Printf("Bob and Alice agree:\n G:\t%s\n H:\t%s\n\n", G, H)

	fmt.Printf("Bob's Password\t: %s\n", m)
	fmt.Printf("Bob's Secret (x): %s\n\n", x)
	fmt.Printf("Bob sends these values:\n xG:\t%s\n xH: \t%s\n\n", xG, xH)
	fmt.Printf("Alice sends challenge:\n c: \t%s\n\n", c)
	fmt.Printf("Bob computes:\n v:\t%s\n r:\t%s\n\n", v, r)

	if !(vG.Equal(a) && vH.Equal(b)) {
		fmt.Println("Verifikasi Gagal!")
	} else {
		fmt.Println("Verifikasi Berhasil")
	}
	fmt.Println("Closing")
	connection.Close()
}
