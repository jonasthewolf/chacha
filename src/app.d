module app;

import std.array : appender;
import std.format : formattedWrite;

import std.stdio;

import key : key;
import chacha : chacha, nonce;



//void main() {
unittest {
	//const key<256 / 8> mykey { }; //{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	immutable ubyte[256/8] inkey =  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
	const auto mykey = key!(256/8)(inkey);
	immutable nonce mynonce = [ 0x09000000, 0x4a000000, 0x0 ];
	auto c = chacha!(20, key!(256 / 8))(mykey, mynonce);
	
	auto block = c.get_next_block();
	auto writer = appender!string();
	foreach ( b ; block) {
			formattedWrite(writer, "%08x ", b);
	}
	auto actualBlock = writer.data;
	auto expectedBlock = "e4e7f110 15593bd1 1fdd0f50 c47120a3 c7f4d1c7 0368c033 9aaa2204 4e6cd4c3 466482d2 09aa9f07 05d7c214 a2028bd9 d19c12b5 b94e16de e883d0cb 4e3c50a2";

	assert (actualBlock == expectedBlock);

	immutable string plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

	for (auto i = 0; i < plaintext.length / 4; i += 4) {
		uint plaintext_block = plaintext[i] << 0 | plaintext[i+1] << 8 | plaintext[i+2] << 16 |  plaintext[i+3] << 24;
		writef("%08x ", plaintext_block);
	}
	writeln();

}

void main() {
	
}