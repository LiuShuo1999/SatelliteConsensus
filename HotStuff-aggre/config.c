#include "config.h"

void hash_sign_struct(char hash[], struct sign_struct *obj){
	unsigned char buf[1024];
	for(int i=0;i<1024;i++)buf[i]=NULL;
	for(int i=0;i<HASH_SIZE;i++)buf[i] = obj->hash[i];

	sprintf(&buf[HASH_SIZE],"%c%d%d%d",obj->tag, obj->id, obj->block_id, obj->vote);

	sha2(buf,80,hash,0);
}

void hash_sign_struct2(char hash[], struct sign_struct2 *obj){
	unsigned char buf[1024];
	for(int i=0;i<1024;i++)buf[i]=NULL;
	for(int i=0;i<HASH_SIZE;i++)buf[i] = obj->hash[i];

	for(int i=0;i<2*f+1;i++)
		for(int j=0;j<SIG_SIZE;j++)
			buf[HASH_SIZE+i*SIG_SIZE+j] = obj->sigs[i][j];

	//for(int i=0;i<(2*f+1)*SIG_SIZE;i++)buf[i+HASH_SIZE] = obj->thres_ch[i];
	sprintf(&buf[HASH_SIZE+(2*f+1)*SIG_SIZE],"%c%d%d%d",obj->tag, obj->id, obj->block_id, obj->vote);
	sha2(buf,80,hash,0);
}

int Sixteen2Ten(char ch){
	if( (ch >= '0') && ( ch <= '9' ) )	return ch - '0';
	return 10 + (ch - 'a');
}
void init_public_key(){
	int string_idx=0;
	int key_idx = 0;
	for(int l=1;l<=13;l++){
		key_idx = 0;
		for(string_idx = 0; string_idx < sizeof(public_key_string[l-1]);){
			public_key[l][key_idx] = Sixteen2Ten(public_key_string[l-1][string_idx])*16+Sixteen2Ten(public_key_string[l-1][string_idx + 1]);
			key_idx = key_idx + 1;
			string_idx = string_idx + 3;
		}

		key_idx = 0;
		for(string_idx = 0; string_idx < sizeof(private_key_string[l-1]);){
			private_key[l][key_idx] = Sixteen2Ten(private_key_string[l-1][string_idx])*16 + Sixteen2Ten(private_key_string[l-1][string_idx + 1]);
			key_idx = key_idx + 1;
			string_idx = string_idx + 3;
		}
		
	}
	
    int num_curves = 0;
//#if uECC_SUPPORTS_secp160r1
//    curves[num_curves++] = uECC_secp160r1();
//#endif
#if uECC_SUPPORTS_secp192r1
    curves[num_curves++] = uECC_secp192r1();
#endif
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