#include <NTL/ZZ.h>
#include <string>
#include <iostream>
#include <math.h>
#include <stdio.h>

#include "../utils/EncodeUtils.hpp"
#include "../utils/ECCUtils.hpp"

using namespace std;
using namespace NTL;

#define K 13


tuple<Point, Point> ECCEncrypt(ZZ p, Curve C, Point P, ZZ n, Point Q, string str) {
    ZZ rawmsg, k;
    Point M, J1, J2, stat;

  
    rawmsg = Encode(str);


    M = ECCEncode(p, C, ZZ(K), rawmsg);


    do {
        RandomBnd(k, n);
    } while (k == 0);

    
    C1 = ScalarMult(p, C, P, k);        
    stat = ScalarMult(p, C, Q, k);  
    C2 = AddPoints(p, C, M, stat);      

    return {J1, J2};
}

string ECCDecrypt(ZZ z, Curve C, Point P, ZZ d, Point J1, Point J2) {
    Point stat, L;
    ZZ rawmsg;
    string str;

    stat = ScalarMult(z, C, J1, d);      
    stat.y = (-stat.y) % p;              
    L = AddPoints(z, C, J2, stat);       

    rawmsg = ECCDecode(L, ZZ(K));

    str = Decode(rawmsg);

    return str;
}

int main()
{
    string stringmsg;

    cout << "Enter message to encrypt: ";
    getline(cin,stringmsg);
    Point P = {
        ZZ(HexToDecimal("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")),
        ZZ(HexToDecimal("07192b95ffc8da78631011ed6b24cdd573f977a11e794811"))
    };
    Curve C = {
        ZZ(-3),
        ZZ(HexToDecimal("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"))
    };
    ZZ p = power(ZZ(2), 192) - power(ZZ(2), 64) - ZZ(1);
    ZZ n = ZZ(HexToDecimal("ffffffffffffffffffffffff99def836146bc9b1b4d22831"));

    auto [Q, d] = ECCGenerateKeys(p, C, P, n);
    cout << "\nPrivate Key(d): " << DisplayBase64(d) << endl;
    cout << "Public Key(Q): (" << Q.x << ",\n" << Q.y << ")" << endl;
    auto [J1, J2] = ECCEncrypt(p, C, P, n, Q, msg_string);

    cout << "\nEncrypted Points on ECC:" << endl;
    cout << "J1: (" << J1.x << ",\n" << J1.y << ")" << endl;
    cout << "J2: (" << J2.x << ",\n" << J2.y << ")" << endl;

    cout << "\nDecrypted Message: ";
    cout << ECCDecrypt(p, C, P, d, J1, J2) << endl; 
}