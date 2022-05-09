package main

import(
	"fmt"
	"local/Ed25519Shamir/EdwardsShamir"
	"local/Ed25519Shamir/shamirutil"
	renshamirutil "github.com/renproject/shamir/shamirutil" 
)

func main(){
	n := 20
	indices := shamirutil.Ed25519RandomIndices(n)
	shares := make(EdwardsShamir.Shares, n)
	k := renshamirutil.RandRange(1, n)
	secret := EdwardsShamir.RandomScalar()
	err := EdwardsShamir.ShareSecret(&shares, indices, secret, k)
	if nil!=err{
		panic("Secret share failed.")
	}
	recon := EdwardsShamir.Open(shares)
	if recon.Eq(&secret){
		fmt.Println("Secret sharing and opening successful")
	}
}