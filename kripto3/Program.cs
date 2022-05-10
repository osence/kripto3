using System.Security.Cryptography;
using System.Xml.Serialization;
using System.Text;

// See https://aka.ms/new-console-template for more information
// Ключ для симметричного криптоалгоритма DES-64 (8 символов)
Console.WriteLine($"enter your DES-64 key:");
string sKey = Console.ReadLine();
sKey = "sdfsdfsd";

// Путь к документу с информацией для шифрования
Console.WriteLine($"Enter the path with text to encrypt:");
string source = Console.ReadLine();
source = ".\\kriptoDoc.txt";

// Путь к документу для вывода зашифрованой информации
Console.WriteLine($"Enter the path to decrypt:");
string destination = Console.ReadLine();
destination = ".\\kriptoDoc2.txt";

// Шифрование документа с помощью DES-64
DesEncryption(source, destination, sKey);

// Шифрование ключа для DES-64 алгоритма с помощью RSA алгоритма
RSAfunc(sKey, source);

// Путь к документу для сверки дешифровки
source = destination;
Console.WriteLine($"Enter the path to check valid decryption:");
destination = Console.ReadLine();
destination = ".\\kriptoDoc3.txt";

// Расшифрование документа
DesDecryption(source, destination, sKey);


/*
    Функция для шифрования документа 
    с помощью криптоалгоритма DES-64
    
    source - Входной документ с текстом
    destination - Выходной документ с шифром
    sKey - Ключ шифрования
*/
void DesEncryption(string source, string destination, string sKey){

    FileStream fsInput = new FileStream(source, FileMode.Open, FileAccess.Read);
    FileStream fsEncrypted = new FileStream(destination, FileMode.Create, FileAccess.Write);
    // DES объект
    DESCryptoServiceProvider DES = new DESCryptoServiceProvider();
    try
    {
        // Устанавливаем ключ и начальный вектор DES
        DES.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
        DES.IV = ASCIIEncoding.ASCII.GetBytes(sKey);
        // Объект для шифровки
        ICryptoTransform desencrypt = DES.CreateEncryptor();
        CryptoStream cryptostream = new CryptoStream(fsEncrypted, desencrypt, CryptoStreamMode.Write);
        byte[] bytearrayinput = new byte[fsInput.Length - 0];
        fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);
        // Шифруем и записываем в файл
        cryptostream.Write(bytearrayinput, 0, bytearrayinput.Length);
        cryptostream.Close();
    }
    catch(Exception e)
    {
        Console.WriteLine(e);
    }
    fsInput.Close();
    fsEncrypted.Close();
    }


/*
    Функция для расшифровки документа 
    с помощью криптоалгоритма DES-64
    
    source - Входной документ с шифром
    destination - Выходной документ с расшифровкой
    sKey - Ключ шифрования
*/
void DesDecryption(string source, string destination, string sKey){

    FileStream fsInput = new FileStream(source, FileMode.Open, FileAccess.Read);
    FileStream fsEncrypted = new FileStream(destination, FileMode.Create, FileAccess.Write);
    // DES объект
    DESCryptoServiceProvider DES = new DESCryptoServiceProvider();
    try
    {
        // Устанавливаем ключ и начальный вектор DES
        DES.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
        DES.IV = ASCIIEncoding.ASCII.GetBytes(sKey);
        // Объект для расшифровки
        ICryptoTransform desencrypt = DES.CreateDecryptor();
        CryptoStream cryptostream = new CryptoStream(fsEncrypted, desencrypt, CryptoStreamMode.Write);
        byte[] bytearrayinput = new byte[fsInput.Length - 0];
        fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);
        // Расшифровываем и записываем в файл
        cryptostream.Write(bytearrayinput, 0, bytearrayinput.Length);
        cryptostream.Close();
    }
    catch(Exception e)
    {
        Console.WriteLine(e);
    }
    fsInput.Close();
    fsEncrypted.Close();
    }


/*
    Функция для шифрования ключа
    с помощью криптоалгоритма RSA-2048
    
    sKey - Строка для шифрования 
    source - Документ для создания и сверки подписи
*/
void RSAfunc(string sKey, string source)
{
    // Объект RSA
    RsaEncryption rsa = new RsaEncryption();
    string cypherText = string.Empty;

    Console.WriteLine($"Public Key: {rsa.GetPublicKey()} \n");
    // По заданию шифруем DES ключ с помощью RSA
    cypherText = rsa.Encrypt(sKey);
    Console.WriteLine($"Encrypted Key: {cypherText}");

    // По заданию расшифровываем DES ключ с помощью RSA
    var plainText = rsa.Decrypt(cypherText);
    Console.WriteLine($"Decrypted Key: {plainText}");

    // По заданию получаем подпись документ
    rsa.GetCaption(source);
}


/*
    Класс RSA-2048 криптоалгоритма
*/
public class RsaEncryption {
    private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
    private RSAParameters _privateKey;
    private RSAParameters _publicKey;


    /*
        Конструктор - определяет значение ключей алгоритма
    */
    public RsaEncryption()
    {
        _privateKey = csp.ExportParameters(true);
        _publicKey = csp.ExportParameters(false);
        return;
    }


    /*
        Функция для получения публичного ключа
    */
    public string GetPublicKey()
    {
        var sw = new StringWriter();
        var xs = new XmlSerializer(typeof(RSAParameters));
        xs.Serialize(sw,_publicKey);
        return sw.ToString();
    }


    /*
        Функция для шифрования текста

        plainText - Текст для шифрования
    */
    public string Encrypt(string plainText)
    {
        csp.ImportParameters(_publicKey);
        var data = Encoding.Unicode.GetBytes(plainText);
        // Расшифровка с помощью встроенной функции Encrypt
        var cypher = csp.Encrypt(data, false);
        return Convert.ToBase64String(cypher); 
    }


    /*
        Функция для расшифрования текста

        plainText - Текст для расшифрования
    */
    public string Decrypt(string cypherText)
    {
        var dataBytes = Convert.FromBase64String(cypherText);
        csp.ImportParameters(_privateKey);
        // Расшифровка с помощью встроенной функции Encrypt
        var plainText = csp.Decrypt(dataBytes, false);
        return Encoding.Unicode.GetString(plainText);
    }


    /*
        Функция для получения и проверки подписи документа

        source - Путь к документу с текстом
    */
    public byte[] GetCaption(string source)
    {
        FileStream fsInput = new FileStream(source, FileMode.Open, FileAccess.Read);
        byte[] bytearrayinput = new byte[fsInput.Length - 0];
        fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);

        var encoder = new UTF8Encoding();
        byte[] signedBytes  = csp.SignData(bytearrayinput, CryptoConfig.MapNameToOID("SHA512"));
        Console.WriteLine("Подпись");
        foreach(byte b in signedBytes)
        {
            Console.Write(b.ToString("x2"));
        }
        Console.WriteLine("\nПроверка подписи");
        Console.WriteLine(csp.VerifyData(bytearrayinput, CryptoConfig.MapNameToOID("SHA512"), signedBytes));
        fsInput.Close();
        return bytearrayinput;
    }
}



