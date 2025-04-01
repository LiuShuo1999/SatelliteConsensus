#include "hotstuff.h"
#include "thres_signature.h"

/********************************threshold signature****************************************************************************************************************************************************************************************/

void ff(BIG_256_56 r,BIG_256_56 x){
	BIG_256_56 q;
	BIG_256_56_rcopy(q, CURVE_Order_BN254);
	BIG_256_56 y;
	BIG_256_56 xx;
	BIG_256_56_zero(y);
	BIG_256_56_one(xx);
	BIG_256_56 tmp;
	BIG_256_56 tmp1;
	for(int i=0;i<k;i++){
		
		//y+=coeff * xx
		BIG_256_56_modmul(tmp,a[i],xx, q);//tmp = a[i] * xx
		//BIG_256_56_norm(tmp);
		BIG_256_56_add(tmp1,y,tmp);//tmp1 = y + tmp
		//BIG_256_56_norm(tmp1);
		BIG_256_56_copy(y,tmp1);  //y = tmp1
		
		//xx*=x
		BIG_256_56_modmul(tmp,xx,x,q);//tmp = xx * x
		//BIG_256_56_norm(tmp);
		BIG_256_56_copy(xx,tmp);
		//BIG_256_56_norm(xx);
	}
	BIG_256_56_copy(r,y);
}

void lagrange(BIG_256_56 r,int j, int Sx[]){
//	def lagrange(self, S, j):
//	# Assert S is a subset of range(0,self.l)
//	assert len(S) == self.k
//	assert type(S) is set
//	assert S.issubset(range(0,self.l))
//	S = sorted(S)

//	assert j in S
//	assert 0 <= j < self.l
//	mul = lambda a,b: a*b
//	num = reduce(mul, [0 - jj - 1 for jj in S if jj != j], ONE)
//	den = reduce(mul, [j - jj     for jj in S if jj != j], ONE)
//	return num / den
/******************************************************************/
	BIG_256_56 modl;
	BIG_256_56_rcopy(modl,CURVE_Order_BN254);
	
	//	num = reduce(mul, [0 - jj - 1 for jj in S if jj != j], ONE)
	BIG_256_56 num, ZERO, ONE, S_jj, tmp, tmp2, tmp3;
	BIG_256_56_one(num);
	BIG_256_56_zero(ZERO);
	BIG_256_56_one(ONE);
	
	BIG_256_56 tmp_neg;
	for(int jj=0;jj<k;jj++){
		if(Sx[jj] == j) continue;
		//num = num * (0 - S[jj] - 1);
		BIG_256_56_zero(S_jj);
		BIG_256_56_inc(S_jj,Sx[jj]);
		
		//BIG_256_56_sub(tmp,ZERO,S_jj);//tmp = 0 - S[jj]
		BIG_256_56_modneg(tmp_neg, S_jj, modl);
		BIG_256_56_modadd(tmp, ZERO, tmp_neg, modl);
		
		//BIG_256_56_sub(tmp2,tmp,ONE);//tmp2 = tmp - 1
		BIG_256_56_modneg(tmp_neg, ONE, modl);
		BIG_256_56_modadd(tmp2, tmp, tmp_neg, modl);
		
		BIG_256_56_modmul(tmp3, num, tmp2, modl);//tmp3 = num * tmp2
		BIG_256_56_copy(num,tmp3);	// num = tmp3 
	}
	BIG_256_56_norm(num);
	//	den = reduce(mul, [j - jj     for jj in S if jj != j], ONE)
	BIG_256_56 den, BIG_J;
	BIG_256_56_one(den);
	BIG_256_56_zero(BIG_J);
	BIG_256_56_inc(BIG_J,j);
	for(int jj=0;jj<k;jj++){
		if(Sx[jj] == j) continue;
		//den = den * (j - S[jj]);
		BIG_256_56_zero(S_jj);
		BIG_256_56_inc(S_jj,Sx[jj]);
		
		//BIG_256_56_sub(tmp,BIG_J,S_jj);//tmp = j - S[jj]
		BIG_256_56_modneg(tmp_neg, S_jj, modl);
		BIG_256_56_modadd(tmp, BIG_J, tmp_neg, modl);
		
		BIG_256_56_modmul(tmp2, den, tmp, modl);//tmp2 = den * tmp
		BIG_256_56_copy(den,tmp2);
	}
	BIG_256_56_norm(den);
	BIG_256_56_moddiv(r, num, den, modl);

}


void dealer(){

char sk_string[][299] = {
"4c d7 73 1b 6c 7b e2 1e ff 6b e6 80 c0 31 5b a2 b9 46 70 d1 58 fe 8d a6 c3 8d 92 0a c9 ae 09 4d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 
"43 7e 43 a5 bb 8f 71 0a 97 fc 24 36 6f a1 28 2c 31 ec 51 f0 fa 7c 21 e6 87 39 11 3e c9 70 a6 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 
"45 eb a5 ba 47 05 0f 4a 44 03 c0 20 38 ee ac 5c 5f a2 55 d7 e1 0d 0c ad 06 c0 9f ef d5 4c 71 e2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 
"2e fc 34 d6 ce dc bc dc 49 4e 6c be 1c 19 e8 2b 42 c8 fc 86 0c b1 4d e9 a1 24 3e 1d ed 41 6c 83 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
};
char vk_string[][299] = {
"03 08 97 e5 09 86 87 25 a7 a2 38 08 a1 46 42 7a 83 3a 55 b7 cc e7 7b ce 0b f1 91 b8 14 90 ed 7f 37 07 b9 f9 77 ac 24 52 ad b5 c2 2e 35 f3 fe 77 46 09 e1 cb 9e c9 f1 cb f9 d5 9c bd 07 69 0c 1d 8e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 
"03 0a 94 20 a3 b1 97 93 84 81 c6 14 1d 01 97 1c e5 b9 6d 57 73 29 38 13 a5 5d 5b 88 af 9c c1 08 20 0d 1c 0e 28 e5 13 d1 ea f7 c2 91 ea 40 a1 1a 0a 9d d5 53 e8 c4 c0 0c 48 01 9e a3 d4 34 a9 cf 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 
"03 21 b7 90 d2 48 25 20 9f bf 0d 8f fd ee 3d ef e8 91 16 52 ee 4f 85 b0 83 bc b4 b7 4e c0 ba dc 7a 24 c0 3c ab 08 97 de 93 46 bd 08 4b 7c 83 ed b3 d5 d0 bc 48 63 40 98 f5 36 49 13 2d 82 be b7 59 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 
"03 08 5c 42 44 94 0b 76 86 aa 59 95 57 c4 d3 36 46 f0 7a a0 68 5b 89 b1 b2 5a eb 27 5a 91 f7 be 93 11 f4 95 13 e5 2e 1c b7 68 3e 18 d1 06 ab e7 2f 34 f1 9b 1b 49 35 43 43 72 89 68 56 05 94 6a eb 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
};
char vk_STRING[] = "02 01 46 b3 11 81 96 b6 e0 61 46 75 61 c1 de ed b4 6f 80 df ca 03 30 37 42 de dd fd 8e bb 95 ac 71 17 fb fe 69 c0 67 9a 70 0f 7b 2d db 09 13 64 4d 27 1a a1 1d 4f ba 77 d6 ae 98 59 09 0f 7a 97 b1 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
	char sk_ch[10][100];
	char vk_ch[10][100];
	char VK_ch[100];
	for(int i=0;i<10;i++)
		for(int j=0;j<100;j++)
			sk_ch[i][j] = vk_ch[i][j] = NULL;
	for(int i=0;i<100;i++)VK_ch[i] = NULL;

	int string_idx=0;
	int key_idx = 0;
	for(int l=1;l<=4;l++){
		key_idx = 0;
		for(string_idx = 0; string_idx < sizeof(sk_string[l-1]);){
			sk_ch[l][key_idx] = Sixteen2Ten(sk_string[l-1][string_idx])*16+Sixteen2Ten(sk_string[l-1][string_idx + 1]);
			key_idx = key_idx + 1;
			string_idx = string_idx + 3;
		}

		key_idx = 0;
		for(string_idx = 0; string_idx < sizeof(vk_string[l-1]);){
			vk_ch[l][key_idx] = Sixteen2Ten(vk_string[l-1][string_idx])*16 + Sixteen2Ten(vk_string[l-1][string_idx + 1]);
			key_idx = key_idx + 1;
			string_idx = string_idx + 3;
		}
		
	}
	key_idx = 0;
	for(string_idx = 0; string_idx < sizeof(vk_STRING);){
		VK_ch[key_idx] = Sixteen2Ten(vk_STRING[string_idx])*16 + Sixteen2Ten(vk_STRING[string_idx + 1]);
		key_idx = key_idx + 1;
		string_idx = string_idx + 3;
	}


	// printf("sks\n");
	for(int i=0;i<players;i++){
		unsigned char ch[100];
		for(int j=0;j<100;j++)ch[j] = sk_ch[i+1][j];
		BIG_256_56_fromBytes(SKs[i],ch);
	}
	// printf("VKs\n");	
	for(int i=0;i<players;i++){
		unsigned char ch[100];
		octet o = {0, sizeof(ch), ch};
		for(int j=0;j<100;j++)ch[j] = vk_ch[i+1][j];
		o.len = 100;
		ECP2_BN254_fromOctet(&VKs[i],&o);

	}
	// printf("VK\n");
	unsigned char ch[100];
	octet o = {0, sizeof(ch), ch};
	for(int j=0;j<100;j++)ch[j] = VK_ch[j];
	o.len = 100;
	ECP2_BN254_fromOctet(&VK,&o);


}

void SK_sign(ECP_BN254 * sig, ECP_BN254 * point){
	//h ** sk
	// BIG_256_56 num;
    // FP_BN254_redc(num,&SKs[ID-1]);
    // ECP_BN254_copy(sig,point);
    // PAIR_BN254_G1mul(sig,num);

	ECP_BN254_copy(sig,point);
	PAIR_BN254_G1mul(sig,SKs[ID-1]);

	// clock_t start,end;
	// double time;
	// double cpu_time[600];
	// start = clock();

	
	// //h ** sk
	// BIG_256_56 num;
	// for(int i=0;i<players;i++){
	// 	FP_BN254_redc(num,&SKs[i]);
	// 	ECP_BN254_copy(&Sigs[i],&M_point);
	// 	PAIR_BN254_G1mul(&Sigs[i],num);
	// }
	
	// end = clock();
	// time = ((double)(end-start))/CLOCKS_PER_SEC;
	// SK_sign_time[Run_idx] = time;
	
}

int PK_verify_sig_share(int id,ECP_BN254 *sig, ECP_BN254 *point){
// id  target node,  point  msg_point

//	B = self.VKs[i]
//	assert pair(g2, sig) == pair(B, h)
//	return True
	ECP2_BN254 B;
	ECP2_BN254 g2_neg;
	ECP2_BN254_copy(&g2_neg,&g2);
	ECP2_BN254_neg(&g2_neg);
	
    ECP2_BN254_copy(&B,&VKs[id-1]);
    FP12_BN254 v;
    PAIR_BN254_double_ate(&v,&g2_neg,sig,&B,point);
    PAIR_BN254_fexp(&v);
		
    if (FP12_BN254_isunity(&v)){
        //printf("PK_verify_sig_share: Yes\n");
        return 1;
    }else{
        printf("PK_verify_sig_share: No\n");
        return 0;
    }
	
	
// 	clock_t start,end;
// 	double time;
// 	double cpu_time[600];
// 	start = clock();
	
// //	B = self.VKs[i]
// //	assert pair(g2, sig) == pair(B, h)
// //	return True
// 	ECP2_BN254 B;
// 	ECP2_BN254 g2_neg;
// 	ECP2_BN254_copy(&g2_neg,&g2);
// 	ECP2_BN254_neg(&g2_neg);
// 	for(int i=0;i<players;i++){

// 		ECP2_BN254_copy(&B,&VKs[i]);
// 		FP12_BN254 v;
// 		PAIR_BN254_double_ate(&v,&g2_neg,&Sigs[i],&B,&M_point);
// 		PAIR_BN254_fexp(&v);
		
// //		if (FP12_BN254_isunity(&v)){
// //			printf("PK_verify_sig_share[%d]: Yes %d",i,timex);
// //		}else{
// //			printf("PK_verify_sig_share[%d]: No %d",i,timex);
// //			
// //		}
// 	}

// 	end = clock();
// 	time = ((double)(end-start))/CLOCKS_PER_SEC;
// 	PK_verify_sig_share_time[Run_idx] = time;
// 	//printf("PK_verify_sig_share %d : %f\n",players,time);
	
}

int PK_verify_sig(ECP_BN254 *sig, ECP_BN254 *point){
//	assert pair(sig, g2) == pair(h, self.VK)
//  return True

	ECP2_BN254 g2_neg;
	ECP2_BN254_copy(&g2_neg,&g2);
	ECP2_BN254_neg(&g2_neg);
	FP12_BN254 v;
	PAIR_BN254_double_ate(&v,&g2_neg,sig,&VK,point);
	PAIR_BN254_fexp(&v);
	
	if (FP12_BN254_isunity(&v)){
		//printf("PK_verify_sig: Yes1\n");
		return 1;
	}else{
		printf("PK_verify_sig: No12\n");
        return 0;
    }


// 	clock_t start,end;
// 	double time;
// 	double cpu_time[600];
// 	start = clock();
	
	
// //	assert pair(sig, g2) == pair(h, self.VK)
// //  return True
// 	ECP2_BN254 g2_neg;
// 	ECP2_BN254_copy(&g2_neg,&g2);
// 	ECP2_BN254_neg(&g2_neg);
// 	FP12_BN254 v;
// 	PAIR_BN254_double_ate(&v,&g2_neg,&SIG,&VK,&M_point);
// 	PAIR_BN254_fexp(&v);
	
// 	end = clock();
// 	time = ((double)(end-start))/CLOCKS_PER_SEC;
// 	PK_verify_sig_time[Run_idx] = time;
// 	//printf("PK_verify_sig:%f\n",time);
	
// 	if (FP12_BN254_isunity(&v)){
// 		printf("PK_verify_sig: Yes\n");
		
// 	}else{
// 		printf("PK_verify_sig: No\n");
// 	}
}

void PK_sig_combine_share(ECP_BN254 *c_sig, ECP_BN254 Sigs_x[], int Sx[]){
	
	//	def combine_shares(self, (U,V,W), shares):
	//	# sigs: a mapping from idx -> sig
	//	S = set(shares.keys())
	//	assert S.issubset(range(self.l))

	//	# ASSUMPTION
	//	# assert self.verify_ciphertext((U,V,W))

	//	mul = lambda a,b: a*b
	//	res = reduce(mul, [sig ** self.lagrange(S, j) for j,sig in sigs.iteritems()], 1)
    //  return res
	
	
	// clock_t start,end;
	// double time;
	// double cpu_time[600];
	// start = clock();
	
	
	BIG_256_56 larg;
	ECP_BN254 tmp;
	ECP_BN254 r[20];
	//ECP_BN254 res;
	//printf("k=%d\n",k);
	for(int j=0 ; j<k ; j++){
		
//		share ** self.lagrange(S, j)
		// lagrange(&larg,Sx[j],Sx);
		// //lagrange(&larg,j);
		// FP_BN254_redc(larg_num,&larg);
		
		// ECP_BN254_copy(&tmp,&Sigs_x[j]);
		
		// if(sign_FP(&larg)){
		// 	// negative
		// 	FP_BN254 larg_tmp;
		// 	BIG_256_56 larg_num_tmp;
		// 	FP_BN254_neg(&larg_tmp,&larg);
		// 	FP_BN254_redc(larg_num_tmp,&larg_tmp);
		// 	PAIR_BN254_G1mul(&tmp,larg_num_tmp);
		// 	ECP_BN254_neg(&tmp);
		// }else{
		// 	FP_BN254_redc(larg_num,&larg);
		// 	PAIR_BN254_G1mul(&tmp,larg_num);
		// }
		// ECP_BN254_copy(&r[j],&tmp);	

		lagrange(larg,Sx[j],Sx);
		ECP_BN254_copy(&tmp,&Sigs_x[j]);
		PAIR_BN254_G1mul(&tmp,larg);
		ECP_BN254_copy(&r[j],&tmp);	
	}
	
	for(int j=1 ; j<k ; j++){
		ECP_BN254_add(&r[0],&r[j]);
	}
	ECP_BN254_copy(c_sig,&r[0]);	
	

	// end = clock();
	// time = ((double)(end-start))/CLOCKS_PER_SEC;
	// PK_sig_combine_share_time[Run_idx] = time;
	// //printf("PK_sig_combine_share:%f\n",time);
	

}





