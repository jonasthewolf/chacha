
@nogc uint read_as_little_endian(in ubyte[] b) {
//	static assert(b.length == 4);
	return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
}

@nogc uint read_as_little_endian(in uint value) {
	return value;
//	const ubyte[4]b = cast(const ubyte[4])value;
//	return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
}
