module app;

import jw.crypto.algorithm.chacha : chacha, nonce;
import jw.crypto.symmetrickey : key;

import std.array : appender;
import std.format : formattedWrite;

import std.stdio;



/// keystream Function Test Vector #1
@system unittest {
	immutable ubyte[256/8] inkey =  0;
	const auto mykey = key!(256/8)(inkey);
	immutable nonce mynonce = [ 0x00000000, 0x00000000, 0x0 ];
	auto c = chacha!(20, key!(256 / 8))(mykey, mynonce);
	
	ubyte[64] keystream; 
	c.get_keystream(keystream, 0);
	auto writer = appender!string();
	foreach ( uint b ; keystream) {
			formattedWrite(writer, "%02x ", (b));
	}
	immutable actual = writer.data;
	immutable expected = "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28 " ~
	                     "bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7 " ~
						 "da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37 " ~
						 "6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86 ";
	assert (actual == expected);
}

/// keystream Function Test Vector #2
@system unittest {
	immutable ubyte[256/8] inkey =  0;
	const auto mykey = key!(256/8)(inkey);
	immutable nonce mynonce = [ 0x00000000, 0x00000000, 0x0 ];
	auto c = chacha!(20, key!(256 / 8))(mykey, mynonce);
	
	ubyte[64] keystream; 
	c.get_keystream(keystream, 1);
	auto writer = appender!string();
	foreach ( uint b ; keystream) {
			formattedWrite(writer, "%02x ", (b));
	}
	immutable actual = writer.data;
	immutable expected = "9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d cb " ~
						 "0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed 29 b7 " ~
						 "21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5 31 ed 1f " ~
						 "28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f ";
	assert (actual == expected);
}

/// keystream Function Test Vector #3
@system unittest {
	immutable ubyte[256/8] inkey = [31:1];
	const auto mykey = key!(256/8)(inkey);
	immutable nonce mynonce = [ 0x00000000, 0x00000000, 0x0 ];
	auto c = chacha!(20, key!(256 / 8))(mykey, mynonce);
	
	ubyte[64] keystream; 
	c.get_keystream(keystream, 1);
	auto writer = appender!string();
	foreach ( uint b ; keystream) {
			formattedWrite(writer, "%02x ", (b));
	}
	immutable actual = writer.data;
	immutable expected = "3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd 83 " ~
						 "20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a 8e ca " ~ 
						 "00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd 4e 27 36 " ~ 
						 "44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0 ";
	assert (actual == expected);
}

/// keystream Function Test Vector #4
@system unittest {
	immutable ubyte[256/8] inkey = [1:0xff];
	const auto mykey = key!(256/8)(inkey);
	immutable nonce mynonce = [ 0x00000000, 0x00000000, 0x0 ];
	auto c = chacha!(20, key!(256 / 8))(mykey, mynonce);
	
	ubyte[64] keystream; 
	c.get_keystream(keystream, 2);
	auto writer = appender!string();
	foreach ( uint b ; keystream) {
			formattedWrite(writer, "%02x ", (b));
	}
	immutable actual = writer.data;
	immutable expected = "72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32 8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca 13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09 24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96 ";
	assert (actual == expected);
}

/// keystream Function Test Vector #5
@system unittest {
	immutable ubyte[256/8] inkey;
	const auto mykey = key!(256/8)(inkey);
	immutable nonce mynonce = [ 0x00000000, 0x00000000, 0x02000000 ];
	auto c = chacha!(20, key!(256 / 8))(mykey, mynonce);
	
	ubyte[64] keystream; 
	c.get_keystream(keystream, 0);
	auto writer = appender!string();
	foreach ( uint b ; keystream) {
			formattedWrite(writer, "%02x ", (b));
	}
	immutable actual = writer.data;
	immutable expected = "c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd 1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7 8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7 5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d ";
	assert (actual == expected);
}

/// Encryption Test Vector #1
@system unittest {
	immutable ubyte[256/8] inkey =  0;
	const auto mykey = key!(256/8)(inkey);
	immutable nonce mynonce = [ 0x00000000, 0x00000000, 0x0 ];
	auto c = chacha!(20, key!(256 / 8))(mykey, mynonce);
	
	ubyte[64] keystream; 
	c.get_keystream(keystream, 0);
	immutable ubyte[64] plaintext =  0;
	auto ciphertext = new ubyte[64];
	ciphertext[] = plaintext[] ^ keystream[];
	auto writer = appender!string();
	foreach ( uint b ; ciphertext) {
			formattedWrite(writer, "%02x ", (b));
	}

	immutable actual = writer.data;
	immutable expected = "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28 bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7 da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37 6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86 ";
	assert (actual == expected);
}

/// Encryption Test Vector #2
@system unittest {
	immutable ubyte[256/8] inkey =  [31:1];
	const auto mykey = key!(256/8)(inkey);
	immutable nonce mynonce = [ 0x00000000, 0x00000000, 0x02000000 ];
	auto c = chacha!(20, key!(256 / 8))(mykey, mynonce);
	
	immutable ubyte[] plaintext = cast(immutable ubyte[])"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
	auto keystream = new ubyte[384];
	c.get_keystream(keystream[0..64], 1);
	c.get_keystream(keystream[64..128], 2);
	c.get_keystream(keystream[128..192], 3);
	c.get_keystream(keystream[192..256], 4);
	c.get_keystream(keystream[256..320], 5);
	c.get_keystream(keystream[320..384], 6);
	auto ciphertext = new ubyte[plaintext.length];
	ciphertext[] = plaintext[] ^ keystream[];
	auto writer = appender!string();
	foreach ( uint b ; ciphertext) {
			formattedWrite(writer, "%02x ", (b));
	}

	immutable actual = writer.data;
	immutable expected = "a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70 41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec 2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05 0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d 40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e 20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50 42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c 68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66 42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28 e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b 08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84 a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0 8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f 58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62 be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6 98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85 14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab 7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd c4 fd 80 6c 22 f2 21 ";
	assert (actual == expected);
}

/// Encryption Test Vector #3
@system unittest {
	immutable ubyte[256/8] inkey = [0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0];
	const auto mykey = key!(256/8)(inkey);
	immutable nonce mynonce = [ 0x00000000, 0x00000000, 0x02000000 ];
	auto c = chacha!(20, key!(256 / 8))(mykey, mynonce);
	
	auto keystream = new ubyte[128];
	c.get_keystream(keystream[0..64], 42);
	c.get_keystream(keystream[64..128], 43);
	immutable ubyte[] plaintext = cast(immutable ubyte[])"'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";
	auto ciphertext = new ubyte[plaintext.length];
	ciphertext[] = plaintext[] ^ keystream[];
	auto writer = appender!string();
	foreach ( uint b ; ciphertext) {
			formattedWrite(writer, "%02x ", (b));
	}

	immutable actual = writer.data;
	immutable expected = "62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df 5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf 16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71 fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6 1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77 04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1 87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1 ";
	assert (actual == expected);
}



void main()
{
	// Needed to execute unit tests
}



