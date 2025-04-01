#include "config.h"


int sign_FP(FP_BN254 *x){
    // int cp;
    // BIG_256_56 m,pm1d2;
    // FP_BN254 y;
    // BIG_256_56_rcopy(pm1d2, Modulus_BN254);
    // BIG_256_56_dec(pm1d2,1);
    // BIG_256_56_fshr(pm1d2,1); //(p-1)/2
     
    // FP_BN254_copy(&y,x);
    // FP_BN254_reduce(&y);
    // FP_BN254_redc(m,&y);
    // cp=BIG_256_56_comp(m,pm1d2);
    // return ((cp+1)&2)>>1;
}

void hash_sign_struct(char hash[], struct sign_struct *obj){
	unsigned char buf[1024];
	for(int i=0;i<1024;i++)buf[i]=NULL;
	for(int i=0;i<HASH_SIZE;i++)buf[i] = obj->hash[i];

	sprintf(&buf[HASH_SIZE],"%c%d%d%d",obj->tag, obj->id, obj->block_id, obj->vote);

	sha2(buf,1024,hash,0);
}

void hash_sign_struct2(char hash[], struct sign_struct2 *obj){
	unsigned char buf[1024];
	for(int i=0;i<1024;i++)buf[i]=NULL;
	for(int i=0;i<HASH_SIZE;i++)buf[i] = obj->hash[i];
	for(int i=0;i<THRES_SIG_SIZE;i++)buf[i+HASH_SIZE] = obj->thres_ch[i];
	sprintf(&buf[HASH_SIZE+THRES_SIG_SIZE],"%c%d%d%d",obj->tag, obj->id, obj->block_id, obj->vote);
	sha2(buf,1024,hash,0);
}

void hash2point(ECP_BN254 *point, char str[]){
	// printf("my hash2point\n");
	// for(int i=0;i<32;i++)
	// 	printf("%02x ",str[i]);
	// printf("\n");
	BIG_256_56 M_num,modl;
	BIG_256_56_rcopy(modl,CURVE_Order_BN254);
	BIG_256_56_fromBytesLen(M_num,str,32);
	BIG_256_56_mod(M_num,modl);
	ECP_BN254_copy(point,&G1);
	PAIR_BN254_G1mul(point,M_num);



	// if(sign_FP(&M_FP)){
	// 	// negative num
	// 	FP_BN254 M_FP_neg;
	// 	FP_BN254_neg(&M_FP_neg,&M_FP);
	// 	FP_BN254_redc(M_num,&M_FP);
	// 	ECP_BN254_copy(point,&G1);
	// 	PAIR_BN254_G1mul(point,M_num);
	// 	ECP_BN254_neg(point);
	// }else{
	// 	FP_BN254_redc(M_num,&M_FP);
	// 	ECP_BN254_copy(point,&G1);
	// 	PAIR_BN254_G1mul(point,M_num);
	// }

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

	FP_BN254 ONE;
	FP_BN254 ZERO;
	FP_BN254_zero(&ZERO);
	FP_BN254_one(&ONE);
	
	players = N;
	k = 2 * f + 1;
	
	//sha256 init
	// char test256[]="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	char digest[50];
	hash256 sh256;
	
	int i;
	BIG_256_56 g1_num;
	
	//test BIG_256_56_fshr
	//BIG_256_56_fshr(g1_num,8);
	
	char mc[10] = "geng1";
	
	for(int i=0;i<50;i++)digest[i] = NULL;
	sha2(mc,5,digest,0);
	BIG_256_56_fromBytes(g1_num,digest);
	
	if(!ECP_BN254_generator(&G1)){
		printf("G1 generator Fail\n");
	}
	
	ECP_BN254_copy(&g1,&G1);
	PAIR_BN254_G1mul(&g1,g1_num);
	//ECP_BN254_copy(&g2,&g1);
	
	if (!ECP2_BN254_generator(&G2)){
		printf("G2 generator Fail\n");
		
	}
	ECP2_BN254_copy(&g2,&G2);
	PAIR_BN254_G2mul(&g2,g1_num);
	
	
	// for(int i=0;i<50;i++)digest[i] = NULL;
	// HASH256_init(&sh256);
	// for (i=0;test256[i]!=0;i++) HASH256_process(&sh256,test256[i]);
    // HASH256_hash(&sh256,digest);
	

	dealer();
	
	// for(int i=0;i<50;i++)M[i]=digest[i];
	
	// FP_BN254 M_FP;
	// BIG_256_56 M_num;
	// FP_BN254_fromBytes(&M_FP,M);
	
	// if(sign_FP(&M_FP)){
	// 	// negative num
	// 	FP_BN254 M_FP_neg;
	// 	FP_BN254_neg(&M_FP_neg,&M_FP);
	// 	FP_BN254_redc(M_num,&M_FP);
	// 	ECP_BN254_copy(&M_point,&G1);
	// 	PAIR_BN254_G1mul(&M_point,M_num);
	// 	ECP_BN254_neg(&M_point);
	// }else{
	// 	FP_BN254_redc(M_num,&M_FP);
	// 	ECP_BN254_copy(&M_point,&G1);
	// 	PAIR_BN254_G1mul(&M_point,M_num);
	// }
	
    // //Threshold Signature
    // SK_sign();
    // PK_verify_sig_share();
    // PK_sig_combine_share();
    // PK_verify_sig();


	// //Threshold Encryption
    // PK_encrypt(digest);
    // PK_verify_ciphertext();
    // SK_decrypt_share();
    // PK_verify_share();
    // PK_combine_share();



}