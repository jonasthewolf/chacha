
T rotate_left(T, immutable int num)(T value){
	    static assert(__traits(isUnsigned, T)); // Rotate left is only available for unsigned types.
	    static assert(num < T.sizeof*8); // Number of bits to rotate must be less than bits of T.

	    return (value << num) | (value >> (T.sizeof*8-num));
}
