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
	buffer0 := make([]byte, 1024)
	mLen0, err := connection.Read(buffer0)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	fmt.Println("G", mLen0)
	var G_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer0[:mLen0]), &G_pt)

	//Read H from Alice
	buffer1 := make([]byte, 1024)
	mLen1, err := connection.Read(buffer1)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	fmt.Println("H", mLen1)
	var H_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer1[:mLen1]), &H_pt)

	////Read xG from Alice
	buffer := make([]byte, 1024)
	mLen, err := connection.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	fmt.Println("xG", mLen)
	var xG_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer[:mLen]), &xG_pt)

	//Read xH from Alice
	buffer2 := make([]byte, 1024)
	mLen2, err := connection.Read(buffer2)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	fmt.Println("xH", mLen2)
	var xH_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer2[:mLen2]), &xH_pt)

	//Make Rand c and Send c to Bob
	c := suite.Scalar().Pick(rng)
	buf := bytes.Buffer{}
	suite.Write(&buf, &c)
	fmt.Println("c", len(buf.Bytes()))
	// Send c to Bob
	connection.Write(buf.Bytes())

	//Read vG from Alice
	buffer3 := make([]byte, 1024)
	mLen3, err := connection.Read(buffer3)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	fmt.Println("vG", mLen3)
	var vG kyber.Point
	suite.Read(bytes.NewBuffer(buffer3[:mLen3]), &vG)

	//Read vH from Alice
	buffer4 := make([]byte, 1024)
	mLen4, err := connection.Read(buffer4)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	fmt.Println("vH", mLen4)
	var vH kyber.Point
	suite.Read(bytes.NewBuffer(buffer4[:mLen4]), &vH)

	//Read r form Bob
	buffer5 := make([]byte, 1024)
	mLen5, err := connection.Read(buffer5)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	fmt.Println("r", mLen5)
	var r kyber.Scalar
	if err := suite.Read(bytes.NewBuffer(buffer5[:mLen5]), &r); err != nil {
		log.Fatal("...")
	}

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

	fmt.Printf("Bob and Alice agree:\n G:\t%s\n H:\t%s\n\n", G_pt, H_pt)

	fmt.Printf("Bob sends these values:\n xG:\t%s\n xH: \t%s\n\n", xG_pt, xH_pt)
	fmt.Printf("Alice sends challenge:\n c: \t%s\n\n", c)
	fmt.Printf("\nAlice :\n a:\t%s\n b:\t%s\n\n", a, b)

	fmt.Printf("\nBob :\n a:\t%s\n b:\t%s\n\n", vG, vH)

	//Conditon for Verification a and B
	if !(vG.Equal(a) && vH.Equal(b)) {
		fmt.Println("Verifikasi Gagal!")
	} else {
		fmt.Println("Verifikasi Berhasil")
	}
	fmt.Println("Closed")
	connection.Close()
}
