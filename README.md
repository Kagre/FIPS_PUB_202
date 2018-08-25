# FIPS_PUB_202
Full implementation of FIPS PUB 202 in JavaScript

This is more of an academic implementation than a cryptographically secure and/or bench marking model. I did not take into account operations which run in uniform time, and consolidating the bit vectors into 32 or 64 bit arithmetic. However the detailed output should track byte for byte to the example files given on the NIST web page <a href="http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing">here</a>.

Main functions: SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, RawSHAKE128, RawSHAKE256

Typical Usage within JavaScript:
```JavaScript 
SHA3_224("test".toUTF8ByteArray());
"test".SHA3_224();
SHAKE128([],256));
"".SHAKE128(256);
```

Auxillary functions: String.prototype.toUTF8ByteArray, Array.prototype.fromUTF8ByteArray, Array.prototype.xor, Number.prototype.toBits, bitStringToState, StateToBitString, Keccak, Sponge, KECCAK_f, KECCAK_p, Round, String.prototype.repeat if it doesn't already exist, zString, pad101, initState, BitsToHex, h2b, b2h

Note: the logging code is looking for a `<p id="log"></p>` HTML DOM element to provide feed back into.
