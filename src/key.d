import endianness;
import std.bitmanip;


// Key length in byte
struct key(immutable size_t key_length) {
	alias key_word_size = uint[key_length/4u];
private:
	key_word_size key_bits;
public:
	@disable this();
	
	@nogc this (in ubyte[key_length] inkey) {
		for (auto i = 0; i < key_length; i += 4) {
			key_bits[i/4] = read_as_little_endian(inkey[i..i+4]);
		}
	}
		
	const key_word_size get_key_bits() { return key_bits; }
	const size_t get_key_length() { return key_bits.length; }
}
