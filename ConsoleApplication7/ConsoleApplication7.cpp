#include <FL/Fl_File_Chooser.H>
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Multiline_Output.H>
#include <FL/fl_ask.H>
#include <iostream>
#include <cmath>
#include <fstream>
#include <sstream>
#include <string>

using namespace std;

// Класс для RSA шифрования
// Класс для RSA шифрования
class RSA {
private:
    int p, q;       // Простые числа
    int n, phi;     // Модуль и функция Эйлера
    int e, d;       // Открытый и закрытый ключи

    int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    int modInverse(int a, int m) {
        a = a % m;
        for (int x = 1; x < m; x++) {
            if ((a * x) % m == 1)
                return x;
        }
        return -1;
    }

public:
    RSA() : p(61), q(53) {
        n = p * q;
        phi = (p - 1) * (q - 1);
        e = 17;
        d = modInverse(e, phi);
    }

    int getPublicKeyN() const { return n; }
    int getPublicKeyE() const { return e; }
    int getPrivateKey() const { return d; }

    int encrypt(int m) {
        long long result = 1;
        for (int i = 0; i < e; i++) {
            result = (result * m) % n;
        }
        return result;
    }

    int decrypt(int c) {
        long long result = 1;
        for (int i = 0; i < d; i++) {
            result = (result * c) % n;
        }
        return result;
    }
};

// Класс приложения с GUI
class RSAApp {
private:
    Fl_Window* window;
    Fl_Button* btn_select_file;
    Fl_Button* btn_encrypt;
    Fl_Button* btn_decrypt;
    Fl_Button* btn_encrypt_input;
    Fl_Input* input_file_path;
    Fl_Input* input_text;
    Fl_Multiline_Output* output_result;

    RSA rsa;

    string loadTextFromFile(const char* filename) {
        ifstream file(filename);
        string text;
        if (file.is_open()) {
            getline(file, text, '\0');
            file.close();
        }
        else {
            fl_alert(u8"Не удалось открыть файл.");
        }
        return text;
    }

    void saveTextToFile(const char* filename, const string& text, int n, int e) {
        ofstream file(filename);
        if (file.is_open()) {
            file << text << u8"\nОткрытый ключ: " << n << ", " << e;
            file.close();
        }
        else {
            fl_alert(u8"Не удалось сохранить файл.");
        }
    }

    static void onSelectFile(Fl_Widget* btn, void* data) {
        RSAApp* app = static_cast<RSAApp*>(data);
        const char* filename = fl_file_chooser(u8"Выберите файл", "*", nullptr);
        if (filename) {
            app->input_file_path->value(filename);
        }
    }

    static void onEncrypt(Fl_Widget* btn, void* data) {
        RSAApp* app = static_cast<RSAApp*>(data);
        const char* filename = app->input_file_path->value();
        if (strlen(filename) == 0) {
            fl_alert(u8"Выберите файл.");
            return;
        }

        string message = app->loadTextFromFile(filename);
        if (message.empty()) return;

        ostringstream encrypted_text;
        for (char c : message) {
            int m = static_cast<int>(c);
            int encrypted_char = app->rsa.encrypt(m);
            encrypted_text << encrypted_char << " ";
        }

        string encrypted_filename = "encrypted.txt";
        app->saveTextToFile(encrypted_filename.c_str(), encrypted_text.str(),
            app->rsa.getPublicKeyN(), app->rsa.getPublicKeyE());

        app->output_result->value((u8"Текст зашифрован и сохранён в файл: " + encrypted_filename).c_str());
    }

    static void onDecrypt(Fl_Widget* btn, void* data) {
        RSAApp* app = static_cast<RSAApp*>(data);
        const char* filename = app->input_file_path->value();
        if (strlen(filename) == 0) {
            fl_alert(u8"Выберите файл.");
            return;
        }

        string encrypted_message = app->loadTextFromFile(filename);
        if (encrypted_message.empty()) return; istringstream encrypted_stream(encrypted_message);
        ostringstream decrypted_text;
        int c;

        while (encrypted_stream >> c) {
            int decrypted_char = app->rsa.decrypt(c);
            decrypted_text << static_cast<char>(decrypted_char);
        }

        app->output_result->value((u8"Расшифрованный текст: " + decrypted_text.str()).c_str());
    }

    static void onEncryptInput(Fl_Widget* btn, void* data) {
        RSAApp* app = static_cast<RSAApp*>(data);
        const char* text = app->input_text->value();

        if (strlen(text) == 0) {
            fl_alert(u8"Введите текст для шифрования.");
            return;
        }

        ostringstream encrypted_text;
        for (char c : string(text)) {
            int m = static_cast<int>(c);
            int encrypted_char = app->rsa.encrypt(m);
            encrypted_text << encrypted_char << " ";
        }

        const char* filename = fl_file_chooser(u8"Выберите файл для сохранения", "*.txt", nullptr);
        if (filename) {
            app->saveTextToFile(filename, encrypted_text.str(),
                app->rsa.getPublicKeyN(), app->rsa.getPublicKeyE());
            fl_message(u8"Текст успешно зашифрован и сохранён.");
        }
    }

public:
    RSAApp() {
        window = new Fl_Window(490, 350, u8"RSA Шифрование");

        btn_select_file = new Fl_Button(10, 10, 120, 30, u8"Выбрать файл");
        input_file_path = new Fl_Input(140, 10, 340, 30, "");
        input_file_path->readonly(1);
        btn_select_file->callback(onSelectFile, this);

        input_text = new Fl_Input(115, 50, 365, 30, u8"Введите текст:");

        output_result = new Fl_Multiline_Output(85, 90, 395, 210, u8"Результат:");

        btn_encrypt = new Fl_Button(10, 310, 150, 30, u8"Зашифровать файл");
        btn_encrypt->callback(onEncrypt, this);

        btn_decrypt = new Fl_Button(170, 310, 150, 30, u8"Расшифровать файл");
        btn_decrypt->callback(onDecrypt, this);

        btn_encrypt_input = new Fl_Button(330, 310, 150, 30, u8"Зашифровать текст");
        btn_encrypt_input->callback(onEncryptInput, this);

        window->end();
    }

    void run() {
        window->show();
        Fl::run();
    }
};

int main() {
    RSAApp app;
    app.run();
    return 0;
}