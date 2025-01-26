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
class RSA {
private:
    int p, q;
    int n, phi;
    int e, d;

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
            if ((a * x) % m == 1) return x;
        }
        return -1;
    }

    bool isPrime(int num) {
        if (num <= 1) return false;
        for (int i = 2; i <= sqrt(num); i++) {
            if (num % i == 0) return false;
        }
        return true;
    }

public:
    RSA() : p(61), q(53) { calculateKeys(); }

    void setPrimes(int new_p, int new_q) {
        if (!isPrime(new_p) || !isPrime(new_q)) {
            throw invalid_argument(u8"Оба числа должны быть простыми!");
        }
        p = new_p;
        q = new_q;
        calculateKeys();
    }

    void calculateKeys() {
        n = p * q;
        phi = (p - 1) * (q - 1);

        e = 2;
        while (e < phi && gcd(e, phi) != 1) {
            e++;
        }

        d = modInverse(e, phi);
    }

    int getPublicKeyN() const { return n; }
    int getPublicKeyE() const { return e; }
    int getPrivateKey() const { return d; }

    int encrypt(int m) const {
        long long result = 1;
        for (int i = 0; i < e; i++) {
            result = (result * m) % n;
        }
        return result;
    }

    int decrypt(int c) const {
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
    Fl_Input* input_p;
    Fl_Input* input_q;
    Fl_Input* input_file_path;
    Fl_Input* input_text;
    Fl_Multiline_Output* output_result;

    Fl_Button* btn_set_keys;
    Fl_Button* btn_select_file;
    Fl_Button* btn_encrypt;
    Fl_Button* btn_decrypt;
    Fl_Button* btn_encrypt_input;

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

    static void onEncryptFile(Fl_Widget* btn, void* data) {
        RSAApp* app = static_cast<RSAApp*>(data);
        const char* filename = app->input_file_path->value();
        if (strlen(filename) == 0) {
            fl_alert(u8"Выберите файл для шифрования.");
            return;
        }

        string content = app->loadTextFromFile(filename);
        if (content.empty()) return;

        ostringstream encrypted_content;
        for (char c : content) {
            int m = static_cast<int>(c);
            int encrypted_char = app->rsa.encrypt(m);
            encrypted_content << encrypted_char << " ";
        }

        string output_filename = "encrypted.txt";
        app->saveTextToFile(output_filename.c_str(), encrypted_content.str(), app->rsa.getPublicKeyN(), app->rsa.getPublicKeyE());
        fl_message(u8"Файл успешно зашифрован и сохранён как %s", output_filename.c_str());

        app->output_result->value((u8"Текст зашифрован и сохранён в файл: " + output_filename).c_str());
    }

    static void onDecryptFile(Fl_Widget* btn, void* data) {
        RSAApp* app = static_cast<RSAApp*>(data);
        const char* filename = app->input_file_path->value();
        if (strlen(filename) == 0) {
            fl_alert(u8"Выберите файл для расшифровки.");
            return;
        }

        string content = app->loadTextFromFile(filename);
        if (content.empty()) return;

        istringstream encrypted_content(content);
        ostringstream decrypted_content;
        int encrypted_char;

        while (encrypted_content >> encrypted_char) {
            int decrypted_char = app->rsa.decrypt(encrypted_char);
            decrypted_content << static_cast<char>(decrypted_char);
        }

        string output_filename = "decrypted.txt";
        app->saveTextToFile(output_filename.c_str(), decrypted_content.str(), 0, 0);
        fl_message(u8"Файл успешно расшифрован и сохранён как %s", output_filename.c_str());
        
        int c;
        while (encrypted_content >> c) {
            int decrypted_char = app->rsa.decrypt(c);
            decrypted_content << static_cast<char>(decrypted_char);
        }

        app->output_result->value((u8"Расшифрованный текст: " + decrypted_content.str()).c_str());
    }

public:
    RSAApp() {
        window = new Fl_Window(490, 400, u8"RSA Шифрование");

        input_p = new Fl_Input(115, 10, 100, 30, u8"Введите p:");
        input_q = new Fl_Input(350, 10, 100, 30, u8"Введите q:");

        btn_set_keys = new Fl_Button(10, 50, 460, 30, u8"Установить ключи");
        btn_set_keys->callback(onSetKeys, this);

        btn_select_file = new Fl_Button(10, 90, 120, 30, u8"Выбрать файл");
        input_file_path = new Fl_Input(140, 90, 340, 30, "");
        input_file_path->readonly(1);
        btn_select_file->callback(onSelectFile, this);

        btn_encrypt = new Fl_Button(10, 130, 220, 30, u8"Зашифровать файл");
        btn_encrypt->callback(onEncryptFile, this);

        btn_decrypt = new Fl_Button(240, 130, 220, 30, u8"Расшифровать файл");
        btn_decrypt->callback(onDecryptFile, this);

        input_text = new Fl_Input(115, 170, 365, 30, u8"Введите текст:");

        output_result = new Fl_Multiline_Output(85, 210, 395, 150, u8"Результат:");

        window->end();
    }

    void run() {
        window->show();
        Fl::run();
    }

    static void onSetKeys(Fl_Widget* btn, void* data) {
        RSAApp* app = static_cast<RSAApp*>(data);
        const char* p_str = app->input_p->value();
        const char* q_str = app->input_q->value();

        if (strlen(p_str) == 0 || strlen(q_str) == 0) {
            fl_alert(u8"Введите значения для p и q.");
            return;
        }

        try {
            int p = stoi(p_str);
            int q = stoi(q_str);
            app->rsa.setPrimes(p, q);
            fl_message(u8"Ключи успешно установлены:\nОткрытый ключ (n, e): (%d, %d)\nЗакрытый ключ: %d",
                app->rsa.getPublicKeyN(), app->rsa.getPublicKeyE(), app->rsa.getPrivateKey());
        }
        catch (invalid_argument& e) {
            fl_alert("Ошибка: %s", e.what());
        }
    }

    static void onSelectFile(Fl_Widget* btn, void* data) {
        RSAApp* app = static_cast<RSAApp*>(data);
        const char* filename = fl_file_chooser(u8"Выберите файл", "*", nullptr);
        if (filename) {
            app->input_file_path->value(filename);
        }
    }
};

int main() {
    RSAApp app;
    app.run();
    return 0;
}
