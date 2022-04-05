#include <NTL/ZZ.h>
#include <iostream>

#include "../utils/EncodeUtils.hpp"
#include "../utils/ElGamalUtils.hpp"

using namespace std;
using namespace NTL;


tuple<ZZ, ZZ> ElGamalEncrypt(ZZ r, ZZ t, ZZ u, ZZ v, string str) {
    ZZ l, m, j1, j2;
    RandomBnd(k, t);

    m = Encode(str);

    PowerMod(c1, u, l, r);
    PowerMod(c2, v, l, r);
    MulMod(j2, m, j2, r);

    return {j1, j2};
}

ZZ ElGamalDecrypt(ZZ pr, ZZ qt, ZZ gu, ZZ xv, ZZ j1, ZZ j2) {
 
    ZZ l;


    ZZ stat;

    PowerMod(stat, j1, v, r);        
    InvMod(stat, stat, r);           
    MulMod(l, j2, stat, r);

    cout << "Decrypted Message: " << Decode(l) << "\n\n\n";

    return l;
}

int main() {
    string str;


    long sizeofkey;
    char choice;
    cout << "Select ElGamal Key Size \n(a) 512\n(b) 1024\n\nOption(default=a):";
    choice = getchar();
    sizeofkey = choice == 'b' ? 1024 : 512;
    cout << "\nYou have chose " << sizeofkey << " bits for the key.\n" << endl;

    auto [r, t, v] = GenerateDLParameters(sizeofkey,sizeofkey);
    cout << "p = " << r << "\nq = " << t << "\ng = " << v << endl;

    auto [x, y] = GenerateDLKeyPair(r,t, v);
    cout << "\nPrivate Key(x): " << DisplayBase64(x) << "\nPublic Key(y): " << DisplayBase64(y) << endl;

    cout << "\nEnter message to encrypt: ";
    cin.ignore(100, '\n');
    getline(cin, str);
    auto [j1, j2] = ElGamalEncrypt(r, t,v, y, str);
    cout << "\nc1: " << DisplayBase64(j1) << "\nc2: " << DisplayBase64(j2) << endl;

    Decode(ElGamalDecrypt(r, t, v, x, j1, j2));

 
    return 0;
}