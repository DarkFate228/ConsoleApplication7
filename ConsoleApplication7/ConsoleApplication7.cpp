#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Multiline_Output.H>
#include <FL/Fl_File_Chooser.H>
#include <FL/fl_ask.H>
#include <iostream>
#include <cmath>
#include <string>
#include <sstream>
#include <fstream>

// Функция для вычисления наибольшего общего делителя
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Функция для вычисления обратного элемента по модулю
int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1)
            return x;
    }
    return -1; // если обратный элемент не найден
}

// Функция для генерации ключей RSA
void generateKeys(int& n, int& e, int& d) {
    // Выбираем два простых числа (для простоты взяты маленькие)
    int p = 61, q = 53;
    n = p * q;
    int phi_n = (p - 1) * (q - 1);

    // Выбираем открытое число e
    e = 17;  // Обычно выбирается 17, так как это простое и взаимно простое с (p-1)*(q-1)

    // Вычисляем d (обратный элемент e по модулю phi_n)
    d = modInverse(e, phi_n);
}

// Функция для шифрования
int encrypt(int m, int e, int n) {
    long long result = 1;
    for (int i = 0; i < e; i++) {
        result = (result * m) % n;
    }
    return result;
}

// Функция для расшифрования
int decrypt(int c, int d, int n) {
    long long result = 1;
    for (int i = 0; i < d; i++) {
        result = (result * c) % n;
    }
    return result;
}

// Функция для загрузки текста из файла
std::string loadTextFromFile(const char* filename) {
    std::ifstream file(filename);
    std::string text;
    if (file.is_open()) {
        std::getline(file, text, '\0');  // Читаем весь текст до конца файла
        file.close();
    }
    else {
        fl_alert("Не удалось открыть файл.");
    }
    return text;
}

// Функция для сохранения зашифрованного текста в файл
void saveEncryptedTextToFile(const char* filename, const std::string& encrypted_text, int n, int e) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << encrypted_text << "\nОткрытый ключ: " << n << ", " << e;
        file.close();
    }
    else {
        fl_alert("Не удалось сохранить файл.");
    }
}

// Обработчик кнопки "Зашифровать"
void on_encrypt(Fl_Widget* btn, void* output) {
    auto* output_box = static_cast<Fl_Multiline_Output*>(output);
    Fl_Input* input_file_path = static_cast<Fl_Input*>(btn->user_data());

    const char* filename = input_file_path->value();
    std::string message = loadTextFromFile(filename);
    if (message.empty()) return;

    // Генерация ключей
    int n, e, d;
    generateKeys(n, e, d);

    // Шифруем сообщение
    std::ostringstream encrypted_text;
    for (char c : message) {
        int m = static_cast<int>(c);
        int encrypted_char = encrypt(m, e, n);
        encrypted_text << encrypted_char << " ";
    }

    // Сохраняем зашифрованный текст в файл
    std::string encrypted_filename = "encrypted.txt";
    saveEncryptedTextToFile(encrypted_filename.c_str(), encrypted_text.str(), n, e);

    output_box->value(("Открытый ключ: " + std::to_string(n) + ", " + std::to_string(e) + "\n" +
        "Зашифрованный текст сохранен в файл: " + encrypted_filename).c_str());
}

// Обработчик кнопки "Расшифровать"
void on_decrypt(Fl_Widget* btn, void* output) {
    auto* output_box = static_cast<Fl_Multiline_Output*>(output);
    Fl_Input* input_file_path = static_cast<Fl_Input*>(btn->user_data());
    const char* filename = input_file_path->value();

    std::string encrypted_message = loadTextFromFile(filename);
    if (encrypted_message.empty()) return;

    // Генерация ключей
    int n, e, d;
    generateKeys(n, e, d);

    // Извлекаем зашифрованный текст (до строки с открытым ключом)
    std::istringstream encrypted_stream(encrypted_message);
    std::ostringstream decrypted_text;
    int c;

    // Расшифровываем каждое число
    while (encrypted_stream >> c) {
        int decrypted_char = decrypt(c, d, n);
        decrypted_text << static_cast<char>(decrypted_char);
    }output_box->value(("Открытый ключ: " + std::to_string(n) + ", " + std::to_string(e) + "\n" +
    "Расшифрованный текст: " + decrypted_text.str()).c_str());
}

// Обработчик кнопки "Выбрать файл"
void on_select_file(Fl_Widget* btn, void* input) {
    const char* filename = fl_file_chooser("Выберите файл", "*", nullptr);
    if (filename) {
        static_cast<Fl_Input*>(input)->value(filename);
    }
}

int main(int argc, char** argv) {
    // Создаем окно
    Fl_Window* window = new Fl_Window(400, 300, "RSA Шифрование");

    // Поле для выбора файла
    Fl_Button* btn_select_file = new Fl_Button(10, 10, 120, 30, "Выбрать файл");
    Fl_Input* input_file_path = new Fl_Input(140, 10, 250, 30, "");
    input_file_path->readonly(1);
    btn_select_file->callback(on_select_file, input_file_path);

    // Поле для отображения результата
    Fl_Multiline_Output* output_result = new Fl_Multiline_Output(10, 50, 380, 100, "Результат:");

    // Поле для ввода закрытого ключа (можно добавить, если нужно для расшифровки)
    Fl_Input* input_private_key = new Fl_Input(140, 160, 250, 30, "Закрытый ключ:");

    // Кнопки шифрования и расшифровки
    Fl_Button* btn_encrypt = new Fl_Button(10, 200, 120, 30, "Зашифровать");
    Fl_Button* btn_decrypt = new Fl_Button(140, 200, 120, 30, "Расшифровать");
    btn_encrypt->callback(on_encrypt, output_result);
    btn_decrypt->callback(on_decrypt, output_result);

    // Передаем путь к файлу в callback кнопок
    btn_encrypt->user_data(input_file_path);
    btn_decrypt->user_data(input_file_path);

    // Отображаем окно
    window->end();
    window->show(argc, argv);
    return Fl::run();
}