# gost
Attempting to properly and securely implement the GOST R 34.11-94 cryptographic hash function in pure C.



### notes
`V_all` - all finite words in the alphabet
`Vk` - a set of all words in the alphabet of length
       k bits (k=16,64,256)
`|A|` - length of a word in V_all
`A||B` - concatenation of words A, B, in V_all
.
.
.
`h0` - an initial hash value
`e := g` - assignment of value g to param e
`hUZ` - S-boxes described in GOST28147
