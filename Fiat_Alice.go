package main

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/kyber/v4/util/random"
)

var rng = random.New()

const (
	SERVER_HOST = "localhost"
	SERVER_PORT = "9988"
	SERVER_TYPE = "tcp"
)

func main() {
	//establish connection
	connection, err := net.Dial(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)
	if err != nil {
		panic(err)
	}
	//---------------------------------WORK-FIATSHAMIR-------------------------------------

	suite := suites.MustFind("Ed25519")

	//----------------------------------------------------

	buffer0 := make([]byte, 1024)
	mLen0, err := connection.Read(buffer0)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	G := buffer0[:mLen0]

	buffer1 := make([]byte, 1024)
	mLen1, err := connection.Read(buffer1)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	H := buffer0[:mLen1]

	buffer := make([]byte, 1024)
	mLen, err := connection.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	xG := buffer[:mLen]
	defer connection.Close()

	buffer2 := make([]byte, 1024)
	mLen2, err := connection.Read(buffer2)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	xH := buffer2[:mLen2]

	//Make Rand C and Send the data
	c := suite.Scalar().Pick(rng)
	buf := bytes.Buffer{}
	suite.Write(&buf, &c)

	buffer3 := make([]byte, 1024)
	mLen3, err := connection.Read(buffer3)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	vG := buffer3[:mLen3]
	defer connection.Close()

	buffer4 := make([]byte, 1024)
	mLen4, err := connection.Read(buffer4)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	vH := buffer4[:mLen4]
	defer connection.Close()

	var r kyber.Scalar
	bufBytes := buf.Bytes()
	if err := suite.Read(bytes.NewBuffer(bufBytes), &r); err != nil {
		log.Fatal("...")
	}
	defer connection.Close()

	G_pt := suite.Point().Embed(G, nil)
	H_pt := suite.Point().Embed(H, nil)
	xG_pt := suite.Point().Embed(xG, nil)
	xH_pt := suite.Point().Embed(xH, nil)

	rG := suite.Point().Mul(r, G_pt)
	rH := suite.Point().Mul(r, H_pt)

	cxG := suite.Point().Mul(c, xG_pt)
	cxH := suite.Point().Mul(c, xH_pt)

	a := suite.Point().Add(rG, cxG)
	b := suite.Point().Add(rH, cxH)

	//--------------------------------------------------------------------------------

	fmt.Printf("Bob and Alice agree:\n G:\t%s\n H:\t%s\n\n", G, H)

	fmt.Printf("Bob sends these values:\n xG:\t%s\n xH: \t%s\n\n", xG, xH)
	fmt.Printf("Alice sends challenge:\n c: \t%s\n\n", c)
	fmt.Printf("\nAlice :\n a:\t%s\n b:\t%s\n\n", a, b)

	fmt.Printf("\nBob :\n a:\t%s\n b:\t%s\n\n", vG, vH)

	// if !(vG.Equal(a) && vH.Equal(b)) {
	// 	fmt.Printf("Verifikasi Gagal!")
	// } else {
	// 	fmt.Printf("Verifikasi Berhasil")
	// }
	connection.Close()
}
