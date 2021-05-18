package com.jeejio.lib;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class ReadP12Cert {
    public static void main(String[] args)
    {
        final String KEYSTORE_FILE     = "/home/liyang/dev/ROM/Key/device.p12";
        final String KEYSTORE_PASSWORD = "123456";
        final String KEYSTORE_ALIAS    = "jeejio.device";

        try
        {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(KEYSTORE_FILE);

            // If the keystore password is empty(""), then we have to set
            // to null, otherwise it won't work!!!
            char[] nPassword = null;
            if ((KEYSTORE_PASSWORD == null) || KEYSTORE_PASSWORD.trim().equals(""))
            {
                nPassword = null;
            }
            else
            {
                nPassword = KEYSTORE_PASSWORD.toCharArray();
            }
            ks.load(fis, nPassword);
            fis.close();

            System.out.println("keystore type=" + ks.getType());

            // Now we loop all the aliases, we need the alias to get keys.
            // It seems that this value is the "Friendly name" field in the
            // detals tab <-- Certificate window <-- view <-- Certificate
            // Button <-- Content tab <-- Internet Options <-- Tools menu
            // In MS IE 6.

            // Now once we know the alias, we could get the keys.

            PrivateKey prikey = (PrivateKey) ks.getKey(KEYSTORE_ALIAS, nPassword);
            Certificate cert = ks.getCertificate(KEYSTORE_ALIAS);
            PublicKey pubkey = cert.getPublicKey();

            System.out.println("cert class = " + cert.getClass().getName());
//            System.out.println("cert = " + cert);
//            writeToFile("/home/liyang/dev/ROM/Key/device.cert",cert.getEncoded());
//            System.out.println("public key = " + pubkey);
//            writeToFile("/home/liyang/dev/ROM/Key/device.pub",pubkey.getEncoded());
//            System.out.println("private key = " + prikey);
//            writeToFile("/home/liyang/dev/ROM/Key/device.pri",prikey.getEncoded());
            writeToFile("/home/liyang/dev/ROM/Key/device.cert",new String(Base64.encode(cert.getEncoded(), Base64.DEFAULT)));
            writeToFile("/home/liyang/dev/ROM/Key/device.pub",new String(Base64.encode(pubkey.getEncoded(), Base64.DEFAULT)));
            writeToFile("/home/liyang/dev/ROM/Key/device.pri",new String(Base64.encode(prikey.getEncoded(), Base64.DEFAULT)));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
    public static void  writeToFile(String path, byte[] bytes){
        FileOutputStream outPutStream = null; // ca.jks
        try {
            outPutStream = new FileOutputStream(new File(path));
            outPutStream.write(bytes);
            outPutStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void  writeToFile(String path, String data){
        FileOutputStream outPutStream = null; // ca.jks
        try {
            outPutStream = new FileOutputStream(new File(path));
            outPutStream.write(data.getBytes());
            outPutStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
