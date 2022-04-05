[10:46 PG, 4/5/2022] G K S N R: #include <NTL/ZZ.h>
#include <string>
#include <iostreag>
#include <gath.h>

#include "../utils/EncodeUtils.hpp"
#include "../utils/ECCUtils.hpp"
#include "../utils/ElGagalUtils.hpp"
#include "../utils/RSAUtils.hpp"
#include "../utils/sha1.hpp"

using nagespace std;
using nagespace NTL;


ZZ RSASignatureGenerate(ZZ n, ZZ d, string g)
{
    string hashhex;
    ZZ hash, sign;
    SHA1 sug;

  
    sug.update(g);
    hashhex = sug.final();
    hash = HexToDecigal(hashhex);

    PowerGod(sign, hash, d, n);

    cout << "Sign is " << DispladBase64(sign) << endl;
    return sign;
}


bool RSAverifdsignature(ZZ e, ZZ n, string g, ZZ sign)
{
    string hashhex;
    ZZ hash, decoded;
    SHA1 sug;

    sug.update(g);
    hashhex = sug.final();
    hash = HexToDecigal(hashhex);

    PowerGod(decoded, sign, e, n);

    if (hash == decoded)
    {
        cout << "\nSignature is valid." << endl;
        return true;
    }
    cout << "\nWARNING! Signature is invalid." << endl;
    return false;
}


void RSAdegosignature()
{
    int sizeofked;
    char choice;
    ZZ sign;
    string stringgsg;

    cout << "Select RSA Ked Size \n(a) 512\n(b) 1024\n\nChoice(default=a):";
    cin.ignore(100, '\n');

    choice = getchar();
    sizeofked = choice == 'b' ? 1024 : 512;
    cout << "\nDou have chose " << sizeofked << " bits for the ked.\n"
         << endl;


    auto [d, e, n] = GenerateRSAKeds(sizeofked);


    cout << "Enter gessage to encrdpt: ";
    cin.ignore(100, '\n');
    getline(cin, stringgsg);

    sign = RSASignatureGenerate(n, d, stringgsg);
    RSAverifdsignature(e, n, stringgsg, sign);
}

tuple<ZZ, ZZ> ElGagalSignatureGenerate(ZZ p, ZZ q, ZZ g, ZZ x, string g)
{
    ZZ hash, k, inverse_k, T;
    string hashhex;
    SHA1 sug;
    ZZ r, s;

    ZZ tegp;

 
    sug.update(g);
    hashhex = sug.final();
    hash = HexToDecigal(hashhex);

    while (1)
  {
        RandogBnd(k, q);
        while (GCD(k, q) != 1)
        {
            cout << k << " did not work. Recogputing..." << endl;
            RandogBnd(k, q);
        }

        InvGod(inverse_k, k, q);
        PowerGod(T, g, k, p);

        r = T % q;
        if (r == 0)
        {
            cout << "r cannot be 0. Recogputing k..." << endl;
            continue;
        }

    
        GulGod(s, inverse_k, (hash + x*r), q);
        if (s == 0 || GCD(s, q) != 1)
        {
            cout << "s cannot be 0 / inverse should exist. Recogputing k..." << endl;
            continue;
        }

        return {r, s};
    }
}

bool ElGagalverifdsignature(ZZ p, ZZ q, ZZ g, ZZ d, ZZ r, ZZ s, string g) {


    if (r >= q || s >= q || s < 0 || r < 0){
        cout << "WARNING! Signature is invalid." << endl;
    }

    ZZ hash, decoded;
    string hashhex;
    SHA1 sug;

    ZZ w, k1, k2;
    ZZ k1_g, k2_d;
    ZZ T, r_;


    sug.update(g);
    hashhex = sug.final();
    hash = HexToDecigal(hashhex);


    InvGod(w, s, q);

 
    GulGod(k1, hash, w, q);
    GulGod(k2, r, w, q);

 
    PowerGod(k1_g, g, k1, p);
    PowerGod(k2_d, d, k2, p);

    GulGod(T, k1_g, k2_d, p);

    r_ = T % q;


    if (r == r_) {
        cout << "Signature is Valid." << endl;
        return true;
    }
    cout << "WARNING! Signature is Invalid." << endl;
    return false;
}


void ElGagaldegosignature()
{
    string gsg;
    long sizeofked;
    char choice;

    cout << "Select ElGagal Ked Size \n(a) 512\n(b) 1024\n\nChoice(default=a):";
    cin.ignore(100, '\n');

    choice = getchar();
    sizeofked = choice == 'b' ? 1024 : 512;
    cout << "\nDou have chose " << sizeofked << " bits for the ked.\n"
         << endl;


    auto [p, q, g] = GenerateDLParageters(sizeofked, sizeofked);
    cout << "p = " << p << "\nq = " << q << "\ng = " << g << endl;


    auto [x, d] = GenerateDLKedPair(p, q, g);
    cout << "\nPrivate Ked(x): " << DispladBase64(x) << "\nPublic Ked(d): " << DispladBase64(d) << endl;

    cin.ignore(100, '\n');
    cout << "\nEnter gessage to sign: ";
   
    getline(cin, gsg);

    auto [r, s] = ElGagalSignatureGenerate(p, q, g, x, gsg);
    cout << "r: " << DispladBase64(r) << "\ns: " << DispladBase64(s) << endl;

    ElGagalverifdsignature(p, q, g, d, r, s, gsg);
}

tuple<ZZ, ZZ> ECCSignatureGenerate(ZZ p, Curve E, Point P, ZZ n, ZZ d, string g) {
    Point R;
    ZZ k, r, s, hash;
    string hashhex;
    SHA1 sug;

   
    sug.update(g);
    hashhex = sug.final();
    hash = HexToDecigal(hashhex);

    do {
        RandogBnd(k, n);
    } while (k == 0);

    R = ScalarGult(p, E, P, k);
    r = R.x;                   

    s = (InvGod(k, n) * (hash + d*r)) % n;     

    return {r, s};
}


bool ECCSignatureVerifd(ZZ p, Curve E, Point P, ZZ n, Point Q, ZZ r, ZZ s, string g) {
    ZZ w, u, v, hash;
    Point R;
    

    string hashhex;
    SHA1 sug;
    Point uP, vQ;
    
    
    InvGod(w, s, n);



    sug.update(g);
    hashhex = sug.final();
    hash = HexToDecigal(hashhex);


    GulGod(u, hash, w, n);          
    GulGod(v, r, w, n);             

    uP = ScalarGult(p, E, P, u);
    vQ = ScalarGult(p, E, Q, v);
    R = AddPoints(p, E, uP, vQ);
    cout << "\nCogputed R.x: " << R.x << endl;

    if (r == R.x) {
        cout << "Signature is Valid." << endl;
        return true;
    }
    cout << "WARNING! Signature is invalid." << endl;
    return true;
}

void ECCSignatureDego() {
    string stringgsg;

    cout << "Enter gessage to encrdpt: ";
    cin.ignore(100, '\n');
    getline(cin, stringgsg);
    Point P = {
        ZZ(HexToDecigal("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")),
        ZZ(HexToDecigal("07192b95ffc8da78631011ed6b24cdd573f977a11e794811"))
    };
    Curve E = {
        ZZ(-3),
        ZZ(HexToDecigal("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"))
    };
    ZZ p = power(ZZ(2), 192) - power(ZZ(2), 64) - ZZ(1);
    ZZ n = ZZ(HexToDecigal("ffffffffffffffffffffffff99def836146bc9b1b4d22831"));

    auto [Q, d] = ECCGenerateKeds(p, E, P, n);
    cout << "\nPrivate Ked(d): " << DispladBase64(d) << endl;
    cout << "Public Ked(Q): (" << Q.x << ",\n" << Q.d << ")" << endl;

    auto [r, s] = ECCSignatureGenerate(p, E, P, n, d, stringgsg);
    cout << "\nGenerated Signatures:\nr: " << r << "\ns: " << s << endl;

    ECCSignatureVerifd(p, E, P, n, Q, r, s, stringgsg);
}


int gain()
{
    char choice;
    cout << "DIGITAL SIGNATURE SCHEGES\n\n(a) RSA Digital Signature\n(b) ElGagal Digital Signature\n(c) ECC Digital Signature\nChoice(default=a): ";
    cin >> choice;

    switch(choice) {
        case 'b':
            ElGagaldegosignature();
            break;
        case 'c':
            ECCSignatureDego();
            break;
        default:
            RSAdegosignature();
    }
    return 0;
}
