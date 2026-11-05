#!/usr/bin/env python3
"""E9: is each comparison game winnable for free?

Real secp256k1, random test keys. Controls: the same one-division trick under the wrong sign, and on
BIP340, must fail. Prints counts and exits 0 only if each result is as expected."""
import hashlib, json, pathlib, secrets, sys
p=2**256-2**32-977; n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(A,B):
    if A is None:return B
    if B is None:return A
    if A[0]==B[0] and (A[1]+B[1])%p==0:return None
    l=(3*A[0]*A[0]*pow(2*A[1],-1,p) if A==B else (B[1]-A[1])*pow(B[0]-A[0],-1,p))%p
    x=(l*l-A[0]-B[0])%p; return (x,(l*(A[0]-x)-A[1])%p)
def mul(k,A=G):
    R=None
    while k:
        if k&1:R=add(R,A)
        A=add(A,A);k>>=1
    return R
def neg(A): return (A[0],p-A[1])
def verify(Q,z,r,s):
    w=pow(s,-1,n); X=add(mul(z*w%n),mul(r*w%n,Q)); return X is not None and X[0]%n==r
def H(b): return int.from_bytes(hashlib.sha256(b).digest(),'big')%n
def tag(t,b):
    h=hashlib.sha256(t).digest(); return int.from_bytes(hashlib.sha256(h+h+b).digest(),'big')%n
def x32(A): return A[0].to_bytes(32,'big')
def even(A): return A[1]%2==0
def bip_e(R,Q,m): return tag(b'BIP0340/challenge',x32(R)+x32(Q)+m)
def bip_verify(Q,m,R,s):
    Q2=Q if even(Q) else neg(Q)
    e=bip_e(R,Q,m); X=add(mul(s),neg(mul(e,Q2)))
    return X is not None and even(X) and X[0]==R[0]
N=200
res=dict(cases=N,ecdsa_free_forgery=0,ecdsa_valid_under_original_key=0,ecdsa_wrong_sign=0,bip340_free_forgery=0,bip340_control_own_sig=0)
for i in range(N):
    d=secrets.randbelow(n-1)+1; P=mul(d); z=H(b'approved %d'%i); z2=H(b'never signed %d'%i)
    k=secrets.randbelow(n-1)+1; r=mul(k)[0]%n; s=pow(k,-1,n)*(z+r*d)%n
    assert verify(P,z,r,s)
    a=(z-z2)*pow(r,-1,n)%n; Q=add(P,mul(a))
    res['ecdsa_free_forgery']+=verify(Q,z2,r,s)
    res['ecdsa_valid_under_original_key']+=verify(P,z2,r,s)
    res['ecdsa_wrong_sign']+=verify(add(P,neg(mul(a))),z2,r,s)
    dd=d if even(P) else n-d; m=b'approved %d'%i; m2=b'never signed %d'%i
    kk=secrets.randbelow(n-1)+1; R=mul(kk); kk=kk if even(R) else n-kk; R=mul(kk)
    e=bip_e(R,P,m); ss=(kk+e*dd)%n
    res['bip340_control_own_sig']+=bip_verify(P,m,R,ss)
    # The nearest equivalent: choose a to fit under the old challenge. The new key changes the hash input.
    Q2=add(P,mul(a))
    res['bip340_free_forgery']+=bip_verify(Q2,m2,R,ss) or bip_verify(Q2,m2,R,(ss+a*e)%n) or bip_verify(Q2,m,R,(ss+a*e)%n)
ok=(res['ecdsa_free_forgery']==N and res['ecdsa_valid_under_original_key']==0 and res['ecdsa_wrong_sign']==0
    and res['bip340_control_own_sig']==N and res['bip340_free_forgery']==0)
res['verdict']='PASS' if ok else 'FAIL'
print(json.dumps(res,indent=1))
pathlib.Path(sys.argv[1]).write_text(json.dumps(res,indent=1)+'\n')
sys.exit(0 if ok else 1)
