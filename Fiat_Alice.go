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
	//Read G from Alice
	buffer0 := make([]byte, 10)
	mLen0, err := connection.Read(buffer0)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	G := buffer0[:mLen0]

	//Read H from Alice
	buffer1 := make([]byte, 10)
	mLen1, err := connection.Read(buffer1)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	H := buffer0[:mLen1]

	////Read xG from Alice
	buffer := make([]byte, 10)
	mLen, err := connection.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	xG := buffer[:mLen]

	//Read xH from Alice
	buffer2 := make([]byte, 10)
	mLen2, err := connection.Read(buffer2)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	xH := buffer2[:mLen2]

	//Make Rand c and Send c to Bob
	c := suite.Scalar().Pick(rng)
	buf := bytes.Buffer{}
	suite.Write(&buf, &c)

	//Read vG from Alice
	buffer3 := make([]byte, 10)
	mLen3, err := connection.Read(buffer3)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	vG := buffer3[:mLen3]

	//Read vH from Alice
	buffer4 := make([]byte, 10)
	mLen4, err := connection.Read(buffer4)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	vH := buffer4[:mLen4]

	//Read r form Bob
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

	//mul r and G
	rG := suite.Point().Mul(r, G_pt)
	//mul r and H
	rH := suite.Point().Mul(r, H_pt)

	//mul r and xG
	cxG := suite.Point().Mul(c, xG_pt)
	//mul r and xH
	cxH := suite.Point().Mul(c, xH_pt)

	//add rG and cXG
	a := suite.Point().Add(rG, cxG)
	//add rH and cXH
	b := suite.Point().Add(rH, cxH)

	//--------------------------------------------------------------------------------

	fmt.Printf("Bob and Alice agree:\n G:\t%s\n H:\t%s\n\n", G, H)

	fmt.Printf("Bob sends these values:\n xG:\t%s\n xH: \t%s\n\n", xG, xH)
	fmt.Printf("Alice sends challenge:\n c: \t%s\n\n", c)
	fmt.Printf("\nAlice :\n a:\t%s\n b:\t%s\n\n", a, b)

	fmt.Printf("\nBob :\n a:\t%s\n b:\t%s\n\n", vG, vH)

	//Conditon for Verification a and B
	if !(vG.Equal(a) && vH.Equal(b)) {
		fmt.Printf("Verifikasi Gagal!")
	} else {
		fmt.Printf("Verifikasi Berhasil")
	}
	connection.Close()
}
