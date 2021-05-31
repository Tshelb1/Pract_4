#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
using namespace std;
int main ()
{
CryptoPP::SHA512 obj;
cout «"Имя: " « obj.AlgorithmName() « endl;
cout « "DigestSize:" « obj.DigestSize() « endl;
cout « "BlockSize:" « obj.BlockSize() « endl;
fstream file;
string path = "/home/kirill/timp/Pract4_1";
string str1, str2;
file.open(path);
if(!file.is_open()) {
cout « "Ошибка! Файл не открыт!" « endl;
return 1;
}
while(true) {
getline(file,str1);
if (file.fail())
break;
str2 += str1;
}
cout « "Содержимое файла: " « str2 « endl;
vector<byte> digest (obj.DigestSize());
obj.Update(reinterpret_cast<const byte*>(str2.data()),str2.size()); 
obj.Final(digest.data()); 
CryptoPP::StringSource(digest.data(),digest.size(),true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(cout))); 
cout « endl;
return 0;
}