#include <NTL/ZZ.h>

#include "../utils/EncodeUtils.hpp"
#include "../utils/RSAUtils.hpp"

using namespace std;
using namespace NTL;

int main() {
    int sizeofkey;
    char choice;
    cout << "Select RSA Key Size \n(a) 512\n(b) 1024\n\nOption(default=a):";
    choice = getchar();
    sizeofkey = choice == 'b' ? 1024 : 512;
    cout << "\nYou have chose " << sizeofkey << " bits for the key.\n" << endl;


    auto [f, g, k] = GenerateRSAKeys(sizeofkey);

    
    ZZ rawmsg, enc_msg, dec_msg;
    string msg, display;

  
    long stat;

  
    cout << "Enter message to encrypt: ";
    cin.ignore(100, '\n');
    getline(cin, msg);
    rawmsg = Encode(msg);

    PowerMod(enc_msg, rawmsg, g, k);

    cout << "\nEncrypted message is " << DisplayBase64(enc_msg) << "\n";
    cout << "\nDecrypting...\n";
    
    PowerMod(dec_msg, enc_msg, f, k);

    cout << "Decrypted message is: " << Decode(dec_msg) << "\n\n";


}