using System;
using System.IO;
using System.Xml.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Xml;

public class Program
{
    public static void Main()
    {
        Console.WriteLine("Процесс создания rsa-ключей Первым пользователем\n");
        // Запишем публичный ключ в файл
        RsaEncryption rsa = new RsaEncryption();

        if (!File.Exists("./publicKey.txt")) File.Create("./publicKey.txt").Close();
        FileStream pkfs = new FileStream("./publicKey.txt", FileMode.Create, FileAccess.Write);
        byte[] pkba = Encoding.Unicode.GetBytes(rsa.GetPublicKey());
        pkfs.Write(pkba, 0, pkba.Length);
        pkfs.Close();
        //Console.WriteLine($"\nПубличный ключ: {rsa.GetPublicKey()} \n");


        Console.WriteLine("Второй пользователь получает от первого публичный ключ\n");
        // Достанем ключ из файла и закодируем сообщение
        pkfs = new FileStream("./publicKey.txt", FileMode.Open, FileAccess.Read);
        pkba = new byte[pkfs.Length - 0];
        pkfs.Read(pkba, 0, pkba.Length);
        string rsapk = Encoding.Unicode.GetString(pkba);
        if (!File.Exists("./message.txt")) File.Create("./message.txt").Close();
        Console.WriteLine($"Введите сообщение:");
        string msg = Console.ReadLine();

        FileStream msgfs = new FileStream("./message.txt", FileMode.Create, FileAccess.Write);
        byte[] msgba = Encoding.Unicode.GetBytes(msg);
        msgfs.Write(msgba, 0 , msgba.Length);
        msgfs.Close();

        if (!File.Exists("./encryptedFile.txt")) File.Create("./encryptedFile.txt").Close();
        if (!File.Exists("./encryptedDesKey.txt")) File.Create("./desKey.txt").Close();
        if (!File.Exists("./desIV.txt")) File.Create("./desIV.txt").Close();

        Console.Write("\nПроцесс шифрования сообщения");
        if (DesEncryption("./message.txt", "./encryptedFile.txt", "./encryptedDesKey.txt", "./desIV.txt", rsapk))
        {
            Console.WriteLine("- Успешно\n");
        }else{
            Console.WriteLine("- Ошибка\n");
        }





        Console.WriteLine("Второй пользователь передает первому следующие данные:\n1) Зашифрованный DES-ключ \n2) Зашифрованный файл \n3) DES-вектор\n");
        FileStream encryptedtextfs = new FileStream("./encryptedFile.txt", FileMode.Open, FileAccess.Read);

        FileStream encrypteddeskeyfs = new FileStream("./encryptedDesKey.txt", FileMode.Open, FileAccess.Read);
        byte[] encrypteddeskeyba = new byte[encrypteddeskeyfs.Length - 0];
        encrypteddeskeyfs.Read(encrypteddeskeyba, 0, encrypteddeskeyba.Length);

        Console.WriteLine("Первый пользователь расшифровывает DES-ключ с помощью приватного ключа - Успешно");
        string deskey = rsa.Decrypt(Encoding.Unicode.GetString(encrypteddeskeyba));
        byte[] deskeyba = Encoding.Unicode.GetBytes(deskey);

        FileStream desivfs = new FileStream("./desIV.txt", FileMode.Open, FileAccess.Read);
        byte[] desivba = new byte[desivfs.Length - 0];
        desivfs.Read(desivba, 0, desivba.Length);
        if (!File.Exists("./decryptedFile.txt")) File.Create("./decryptedFile.txt").Close();
        Console.Write("Первый пользователь расшифровывает файл ");
        if (DesDecryption("./encryptedFile.txt", "./decryptedFile.txt", deskeyba, desivba))
        {
            Console.WriteLine("- Успешно\n");
        }else{
            Console.WriteLine("- Ошибка\n");
        }

        rsa.GetCaption("./decryptedFile.txt");

		Console.WriteLine($"\nСверяем содержимое изначального файла и расшифрованного:");
		
        FileStream fsInputSrc = new FileStream("./message.txt", FileMode.Open, FileAccess.Read);
        byte[] bytearraySrc = new byte[fsInputSrc.Length - 0];
        fsInputSrc.Read(bytearraySrc, 0, bytearraySrc.Length);
        
        FileStream fsInputDst = new FileStream("./decryptedFile.txt", FileMode.Open, FileAccess.Read);
        byte[] bytearrayDst = new byte[fsInputDst.Length - 0];
        fsInputDst.Read(bytearrayDst, 0, bytearrayDst.Length);
        
        if (bytearraySrc.SequenceEqual(bytearrayDst)){
            Console.WriteLine($"Файлы совпали\nПрограмма завершена успешно");
        }else{
            Console.WriteLine($"Файлы не совпали\nПрограмма завершена с ошибкой");
        }
	}



/*
    Функция для шифрования документа 
    с помощью криптоалгоритма DES-64
    
    source - Входной документ с текстом
    destination - Выходной документ с шифром
    sKey - Ключ шифрования
*/
public static Boolean DesEncryption(string msgFile, string encryptedMsgFile, string encryptedDesKeyFile, string desIVFile, string rsapk){

    //Console.Write(File.ReadAllText(source));
    FileStream fsEncrypted = new FileStream(encryptedMsgFile, FileMode.Create, FileAccess.Write);
    FileStream fsDesKeyfile = new FileStream(encryptedDesKeyFile, FileMode.Create, FileAccess.Write);
    FileStream fsDesivfile = new FileStream(desIVFile, FileMode.Create, FileAccess.Write);
    FileStream fsmsgfile = new FileStream(msgFile, FileMode.Open, FileAccess.Read);
    RsaEncryption rsa = new RsaEncryption();
    rsa.SetPublicKey(rsapk);
    // DES объект
    DESCryptoServiceProvider DES = new DESCryptoServiceProvider();

    try
    {
        DES.GenerateKey();
        
        ICryptoTransform desencrypt = DES.CreateEncryptor();
        CryptoStream cryptostream = new CryptoStream(fsEncrypted, desencrypt, CryptoStreamMode.Write);
        // Шифруем и записываем в файл
        byte[] bytearrayinput = new byte[fsmsgfile.Length - 0];
        fsmsgfile.Read(bytearrayinput, 0, bytearrayinput.Length);
        cryptostream.Write(bytearrayinput, 0, bytearrayinput.Length);
        cryptostream.Close();
        
        string encryptedKey = rsa.Encrypt(Encoding.Unicode.GetString(DES.Key));
        byte[] encryptedKeyba = Encoding.Unicode.GetBytes(encryptedKey);
        fsDesKeyfile.Write(encryptedKeyba, 0, encryptedKeyba.Length);
        fsDesivfile.Write(DES.IV, 0, DES.IV.Length);
    }
    catch(Exception e)
    {
        Console.WriteLine(e);
        return false;
    }
    fsEncrypted.Close();
    fsDesKeyfile.Close();
    fsDesivfile.Close();
    return true;
}

/*
    Функция для расшифровки документа 
    с помощью криптоалгоритма DES-64
    
    source - Входной документ с шифром
    destination - Выходной документ с расшифровкой
    sKey - Ключ шифрования
*/
public static Boolean DesDecryption(string source, string destination, byte[] deskeyba, byte[] desivba){

    FileStream fsInput = new FileStream(source, FileMode.Open, FileAccess.Read);
    FileStream fsEncrypted = new FileStream(destination, FileMode.Create, FileAccess.Write);

    // DES объект
    DESCryptoServiceProvider DES = new DESCryptoServiceProvider();
    try
    {
        // Устанавливаем ключ и начальный вектор DES
        DES.Key = deskeyba;
        DES.IV = desivba;

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
        return false;
    }
    fsInput.Close();
    fsEncrypted.Close();
    return true;
}
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

    public void SetPublicKey(string pk)
    {
        // FileStream fspkFile = new FileStream(pkFile, FileMode.Open, FileAccess.Read);
        // var sw = new StringWriter();
        // var xs = new XmlSerializer(typeof(RSAParameters));
        
        // _publicKey =  (RSAParameters)xs.Deserialize(fspkFile);
        // return;
        //get a stream from the string
        var sr = new System.IO.StringReader(pk);
        //we need a deserializer
        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
        //get the object back from the stream

        
        _publicKey = (RSAParameters)xs.Deserialize(sr);
        
        return;
    }
    public void SetPrivateKey(string pk)
    {
        // FileStream fspkFile = new FileStream(pkFile, FileMode.Open, FileAccess.Read);
        // var sw = new StringWriter();
        // var xs = new XmlSerializer(typeof(RSAParameters));
        
        // _publicKey =  (RSAParameters)xs.Deserialize(fspkFile);
        // return;
        //get a stream from the string
        var sr = new System.IO.StringReader(pk);
        //we need a deserializer
        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
        //get the object back from the stream

        
        _privateKey = (RSAParameters)xs.Deserialize(sr);
        
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

    public string GetPrivateKey()
    {
        var sw = new StringWriter();
        var xs = new XmlSerializer(typeof(RSAParameters));
        xs.Serialize(sw,_privateKey);
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
        string password = "itsmypass";
        if (!File.Exists("./encryptedKey.txt")) File.Create("./encryptedKey.txt").Close();
        FileStream fsEncrypted = new FileStream("./encryptedKey.txt", FileMode.Create, FileAccess.Write);
        
        var key = sha256_hash(password);
        DESCryptoServiceProvider DES = new DESCryptoServiceProvider();
        byte[] temp = new byte[8];
        Array.Copy(key, 0, temp, 0, 8);
        DES.Key = temp;
        DES.IV = temp;
        ICryptoTransform desencrypt = DES.CreateEncryptor();
        CryptoStream cryptostream = new CryptoStream(fsEncrypted, desencrypt, CryptoStreamMode.Write);
        byte[] bytearrayinput = Encoding.Unicode.GetBytes(GetPrivateKey());
        cryptostream.Write(bytearrayinput, 0, bytearrayinput.Length);
        cryptostream.Close();
        fsEncrypted.Close();

        Console.WriteLine($"Введите пароль:");
        string userPass = Console.ReadLine();

        if (!File.Exists("./decryptedKey.txt")) File.Create("./decryptedKey.txt").Close();
        FileStream fsDecrypted = new FileStream("./decryptedKey.txt", FileMode.Create, FileAccess.Write);
        FileStream fsEncrypted2 = new FileStream("./encryptedKey.txt", FileMode.Open, FileAccess.Read);
        
        key = sha256_hash(userPass);
        Array.Copy(key, 0, temp, 0, 8);
        DES.Key = temp;
        DES.IV = temp;
        ICryptoTransform desencrypt2 = DES.CreateDecryptor();
        CryptoStream cryptostream2 = new CryptoStream(fsDecrypted, desencrypt2, CryptoStreamMode.Write);
        byte[] bytearrayinput2 = new byte[fsEncrypted2.Length - 0];
        fsEncrypted2.Read(bytearrayinput2, 0 ,bytearrayinput2.Length);
        cryptostream2.Write(bytearrayinput2, 0, bytearrayinput2.Length);
        cryptostream2.Close();
        fsDecrypted.Close();
        fsEncrypted2.Close();

        fsDecrypted = new FileStream("./decryptedKey.txt", FileMode.Open, FileAccess.Read);
        byte[] bytearrayinput3 = new byte[fsDecrypted.Length - 0];
        fsDecrypted.Read(bytearrayinput3, 0 ,bytearrayinput3.Length);
        fsDecrypted.Close();
        SetPrivateKey(Encoding.Unicode.GetString(bytearrayinput3));
        

        
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
        // Чтение файла с текстом
        FileStream fsInput = new FileStream(source, FileMode.Open, FileAccess.Read);
        byte[] bytearrayinput = new byte[fsInput.Length - 0];
        fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);

        // Создание подписи открытого файла
        byte[] signedBytes  = csp.SignData(bytearrayinput, CryptoConfig.MapNameToOID("SHA512"));
        Console.WriteLine($"\nСоздаем подпись документа:");
        // foreach(byte b in signedBytes)
        // {
        //     Console.Write(b.ToString("x2"));
        // }
        // Проверка подписи
        Console.WriteLine($"\nПроизводим проверку подлинности подписи");
        
        if (csp.VerifyData(bytearrayinput, CryptoConfig.MapNameToOID("SHA512"), signedBytes)){
            Console.WriteLine($"Проверка подписи - Успешно");
        }else{
            Console.WriteLine($"Проверка подписи - Ошибка");
        }
        fsInput.Close();
        return bytearrayinput;
    }

    public static Byte[] sha256_hash(String value) {
        Byte[] result;
        using (SHA256 hash = SHA256Managed.Create()) {
            Encoding enc = Encoding.UTF8;
            result = hash.ComputeHash(enc.GetBytes(value));

        }

        return result;
    }
}