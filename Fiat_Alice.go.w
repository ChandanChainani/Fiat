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
	// connection.Write([]byte("Hello Server"))
	//---------------------------------WORK-FIATSHAMIR-------------------------------------

	suite := suites.MustFind("Ed25519")

	//----------------------------------------------------

	buffer0 := make([]byte, 1024)
	mLen0, err := connection.Read(buffer0)
	if err != nil {
		fmt.Println("1 Error reading:", err.Error())
	}
	var G_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer0[:mLen0]), &G_pt)
	// G_by, err := G_pt.MarshalBinary()
	// fmt.Println("G by", G_by)

	buffer1 := make([]byte, 1024)
	mLen1, err := connection.Read(buffer1)
	if err != nil {
		fmt.Println("2 Error reading:", err.Error())
	}
	// H := buffer0[:mLen1]
	var H_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer1[:mLen1]), &H_pt)
	// H_by, err := H_pt.MarshalBinary()
	// fmt.Println("H", string(H))

	buffer := make([]byte, 1024)
	mLen, err := connection.Read(buffer)
	if err != nil {
		fmt.Println("3 Error reading:", err.Error())
	}
	// xG := buffer[:mLen]
	var xG_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer[:mLen]), &xG_pt)
	// xG_by, err := xG_pt.MarshalBinary()
	// defer connection.Close()

	buffer2 := make([]byte, 1024)
	mLen2, err := connection.Read(buffer2)
	if err != nil {
		fmt.Println("4 Error reading:", err.Error())
	}
	// xH := buffer2[:mLen2]
	var xH_pt kyber.Point
	suite.Read(bytes.NewBuffer(buffer2[:mLen2]), &xH_pt)
	// xH_by, err := xH_pt.MarshalBinary()

	//Make Rand C and Send the data
	c := suite.Scalar().Pick(rng)
	buf := bytes.Buffer{}
	suite.Write(&buf, &c)
	// fmt.Println(string(buf.Bytes()))

	connection.Write(buf.Bytes())

	buffer3 := make([]byte, 1024)
	mLen3, err := connection.Read(buffer3)
	if err != nil {
		fmt.Println("5 Error reading:", err.Error())
	}
	// vG := buffer3[:mLen3]
	var vG kyber.Point
	suite.Read(bytes.NewBuffer(buffer3[:mLen3]), &vG)
	// fmt.Println(string(vG))
	// defer connection.Close()

	buffer4 := make([]byte, 1024)
	mLen4, err := connection.Read(buffer4)
	if err != nil {
		fmt.Println("6 Error reading:", err.Error())
	}
	// vH := buffer4[:mLen4]
	var vH kyber.Point
	suite.Read(bytes.NewBuffer(buffer4[:mLen4]), &vH)
	// fmt.Println(vH)
	// defer connection.Close()

	buffer5 := make([]byte, 1024)
	mLen5, err := connection.Read(buffer5)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	// fmt.Println("Buf5", mLen5, buffer5)
	// r := buffer5[:mLen5]
	var r kyber.Scalar
	if err := suite.Read(bytes.NewBuffer(buffer5[:mLen5]), &r); err != nil {
		// fmt.Println(buffer5[:mLen5])
		log.Fatal("...")
	}
	/// // defer connection.Close()

	// fmt.Println(r)
	// G_pt := suite.Point().Embed(G, nil)
	// H_pt := suite.Point().Embed(H, nil)
	// xG_pt := suite.Point().Embed(xG, nil)
	// xH_pt := suite.Point().Embed(xH, nil)

	rG := suite.Point().Mul(r, G_pt)
	rH := suite.Point().Mul(r, H_pt)

	cxG := suite.Point().Mul(c, xG_pt)
	cxH := suite.Point().Mul(c, xH_pt)

	a := suite.Point().Add(rG, cxG)
	b := suite.Point().Add(rH, cxH)

	//--------------------------------------------------------------------------------

	fmt.Printf("Bob and Alice agree:\n G:\t%s\n H:\t%s\n\n", G_pt, H_pt)

	fmt.Printf("Bob sends these values:\n xG:\t%s\n xH: \t%s\n\n", xG_pt, xH_pt)
	fmt.Printf("Alice sends challenge:\n c: \t%s\n\n", c)
	fmt.Printf("\nAlice :\n a:\t%s\n b:\t%s\n\n", a, b)

	fmt.Printf("\nBob :\n a:\t%s\n b:\t%s\n\n", vG, vH)

	// if !(vG.Equal(a) && vH.Equal(b)) {
	// 	fmt.Printf("Verifikasi Gagal!")
	// } else {
	// 	fmt.Printf("Verifikasi Berhasil")
	// }
	fmt.Println("Closed")
	connection.Close()
}
