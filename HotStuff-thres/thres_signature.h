#ifndef THRES_SIGNATURE_H
#define THRES_SIGNATURE_H
#include "hotstuff.h"


//Threshold signature
void ff(BIG_256_56 r,BIG_256_56 x);
void lagrange(BIG_256_56 r,int j,int S[]);
void dealer();
void SK_sign(ECP_BN254 * sig, ECP_BN254 * point);
int PK_verify_sig_share(int id,ECP_BN254 *sig, ECP_BN254 *point);
int PK_verify_sig(ECP_BN254 *sig, ECP_BN254 *point);
void PK_sig_combine_share(ECP_BN254 *c_sig, ECP_BN254 SIGS[], int Sx[]);


#endif /* thres_signature.h */