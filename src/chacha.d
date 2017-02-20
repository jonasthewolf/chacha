
import std.format : formattedWrite;
import std.bitmanip : nativeToLittleEndian;

import rotate;
import endianness;
import key;

alias rotate_left7 = rotate_left!(uint, 7);
alias rotate_left8 = rotate_left!(uint, 8);
alias rotate_left12 = rotate_left!(uint, 12);
alias rotate_left16 = rotate_left!(uint, 16);


static immutable size_t inner_state_size = 16u;
alias inner_state = uint[inner_state_size];

static immutable auto nonce_length = 3u;
alias nonce = uint[nonce_length];

struct chacha(immutable size_t rounds, alias k) {
	static assert(rounds % 2u == 0);  // Number of rounds has to be even.

private:
	static immutable size_t block_number_index = 12u;
	
	inner_state state;
public:
	@disable this();
	
	@nogc this(ref const k usedkey, ref const nonce n) {
		state[0] = read_as_little_endian(0x61707865);
		state[1] = read_as_little_endian(0x3320646e);
		state[2] = read_as_little_endian(0x79622d32);
		state[3] = read_as_little_endian(0x6b206574);
	    
	    reset_block_counter();
	    set_key(usedkey);
	    set_nonce(n);
	}
	
	nothrow ~this() {
	}

	static immutable size_t block_size = 64u / 4u;
	alias block_type = uint[block_size];

	void get_keystream(ref ubyte[] keystream, uint blocknumber) {
		state[block_number_index] = blocknumber;
		auto working_state = state;
		for (int i = 0; i < rounds/2; ++i) {
			quarter_round(working_state, 0u, 4u, 8u, 12u);
			quarter_round(working_state, 1u, 5u, 9u, 13u);
			quarter_round(working_state, 2u, 6u, 10u, 14u);
			quarter_round(working_state, 3u, 7u, 11u, 15u);
			quarter_round(working_state, 0u, 5u, 10u, 15u);
			quarter_round(working_state, 1u, 6u, 11u, 12u);
			quarter_round(working_state, 2u, 7u, 8u, 13u);
			quarter_round(working_state, 3u, 4u, 9u, 14u);
		}
		working_state[] += state[];
		serialize_inner_state(keystream, working_state);
	}

	void get_next_keystream(ref ubyte[] keystream) {
		get_keystream(keystream, state[block_number_index] + 1);
	}
	

private:
	void reset_block_counter() {
		state[block_number_index] = 0;
	}

	void set_key(const ref k usedkey) {
		for (auto i = 0; i < usedkey.get_key_length(); i++) {
	    	state[4+i] = usedkey.get_key_bits()[i];
	    }
	}

	void set_nonce(const ref nonce n) {
		state[13] = n[0];
	    state[14] = n[1];
	    state[15] = n[2];
	}

	void quarter_round(ref inner_state state, immutable size_t a, immutable size_t b,
			immutable size_t c, immutable size_t d) {
		state[a] += state[b];
		state[d] ^= state[a];
		state[d] = rotate_left16(state[d]);
		state[c] += state[d];
		state[b] ^= state[c];
		state[b] = rotate_left12(state[b]);
		state[a] += state[b];
		state[d] ^= state[a];
		state[d] = rotate_left8(state[d]);
		state[c] += state[d];
		state[b] ^= state[c];
		state[b] = rotate_left7(state[b]);
    }
	
	void serialize_inner_state(ref ubyte[] keystream, inner_state state) {
		for (int i = 0; i < state.length; i++) {
			keystream[(i*4)..(i*4+4)] = nativeToLittleEndian(state[i]);
		}
	}
	
};






