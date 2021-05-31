#include "AlgorithmAES.h"
#include "AlgorithmGost.h"

int main ()
{
    bool isTrue = true;;
    string f_in, f_out,f_iv,password, mode;
    do {
        cout << " Выбирете режим работы: \n";
        cout << "  EncodeG - шифрование с использованием алгоритма \"GOST\"" << endl;
        cout << "  DecodeG - расшифрование с использованием алгоритма \"GOST\"" << endl;
        cout << "  EncodeA - шифрование с использованием алгоритма \"AES\"" << endl;
        cout << "  DecodeA - расшифрование с использованием алгоритма \"AES\"" << endl;
        cout << "  Exit - для выхода из программы" << endl;
        cout << "   -> ";
        cin >> mode;
        if (mode == "EncodeG") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmGost enc(f_in,f_out,password);
                enc.encodeGost(enc);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "EncodeA") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmAES enc(f_in,f_out,password);
                enc.encodeAES(enc);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "DecodeG") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
            cin >> f_iv;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmGost dec(f_in,f_out,password,f_iv);
                dec.decodeGost(dec);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if (mode == "DecodeA") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
            cin >> f_iv;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmAES dec(f_in,f_out, password, f_iv );
                dec.decodeAES(dec);
            } catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if (mode == "Exit") {
            isTrue = false;
            break;
        }
    } while (isTrue != false);
    return 0;
}