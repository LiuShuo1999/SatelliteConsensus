#include "config.h"

// Convert a hexadecimal character to its decimal value
int Sixteen2Ten(char ch) {
	if ((ch >= '0') && (ch <= '9')) return ch - '0';
	return 10 + (ch - 'a');
}

void init_public_key() {
	int string_idx = 0;
	int key_idx = 0;

	// Initialize public and private keys from their string representations
	for (int l = 1; l <= 13; l++) {
		key_idx = 0;
		// Convert public key string to byte array
		for (string_idx = 0; string_idx < sizeof(public_key_string[l - 1]);) {
			public_key[l][key_idx] = Sixteen2Ten(public_key_string[l - 1][string_idx]) * 16 + Sixteen2Ten(public_key_string[l - 1][string_idx + 1]);
			key_idx++;
			string_idx += 3;
		}

		key_idx = 0;
		// Convert private key string to byte array
		for (string_idx = 0; string_idx < sizeof(private_key_string[l - 1]);) {
			private_key[l][key_idx] = Sixteen2Ten(private_key_string[l - 1][string_idx]) * 16 + Sixteen2Ten(private_key_string[l - 1][string_idx + 1]);
			key_idx++;
			string_idx += 3;
		}
	}

	int num_curves = 0;

	// Initialize supported elliptic curves
#if uECC_SUPPORTS_secp192r1
	curves[num_curves++] = uECC_secp192r1();
#endif
	// Uncomment the following lines to support additional curves
	//#if uECC_SUPPORTS_secp160r1
	//    curves[num_curves++] = uECC_secp160r1();
	//#endif
	//#if uECC_SUPPORTS_secp224r1
	//    curves[num_curves++] = uECC_secp224r1();
	//#endif
	//#if uECC_SUPPORTS_secp256r1
	//    curves[num_curves++] = uECC_secp256r1();
	//#endif
	//#if uECC_SUPPORTS_secp256k1
	//    curves[num_curves++] = uECC_secp256k1();
	//#endif
}

void hash_sign_struct(char *hash, struct sign_struct *obj) {
	unsigned char buf[1024];
	// Initialize buffer to NULL
	for (int i = 0; i < 1024; i++) buf[i] = NULL;

	// Copy hash from object to buffer
	for (int i = 0; i < HASH_SIZE; i++) buf[i] = obj->hash[i];

	// Append other fields of the struct to the buffer
	sprintf(&buf[HASH_SIZE], "%c%d%d%d", obj->tag, obj->id, obj->block_id, obj->vote);

	// Compute SHA-256 hash of the buffer
	sha2(buf, 1024, hash, 0);
}