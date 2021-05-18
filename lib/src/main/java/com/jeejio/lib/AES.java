package com.jeejio.lib;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {
    public static final String KEY_ALGORITHM = "AES";
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";

    public static void encryptionFile(String srcFile, String destionFile,  String encodedKey) throws Exception {
        int len = 0;
        byte[] buffer = new byte[16];
        byte[] cipherbuffer = null;
        byte[] ive = new byte[16];
        // decode the base64 encoded string
        Key sessionKey = new SecretKeySpec(Base64.decode(encodedKey, 0), KEY_ALGORITHM);

        // 使用会话密钥对文件加密。
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM, new BouncyCastleProvider());
        IvParameterSpec iv = new IvParameterSpec(ive);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, iv);

        FileInputStream fis = new FileInputStream(new File(srcFile));
        FileOutputStream fos = new FileOutputStream(new File(destionFile));
//        fis.skip(12);
        // 读取原文，加密并写密文到输出文件。
        while ((len = fis.read(buffer)) != -1) {
            cipherbuffer = cipher.update(buffer, 0, len);
            fos.write(cipherbuffer);
            fos.flush();
        }
        cipherbuffer = cipher.doFinal();
        fos.write(cipherbuffer);
        fos.flush();

        if (fis != null)
            fis.close();
        if (fos != null)
            fos.close();
    }

    public static void descryptionFile(String srcFile, String destionFile,String decodedKey) throws Exception {
        int len = 0;
        byte[] buffer = new byte[32];
        byte[] plainbuffer = null;
        byte[] ive = new byte[16];
        byte[] key = decodedKey.getBytes();
        System.out.println("key.length: "+key.length);
        Key sessionKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM, new BouncyCastleProvider());
        IvParameterSpec iv = new IvParameterSpec(ive);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, iv);

        FileInputStream fis = new FileInputStream(new File(srcFile));
        FileOutputStream fos = new FileOutputStream(new File(destionFile));
        //fis.skip(12);
        while ((len = fis.read(buffer)) != -1) {
            plainbuffer = cipher.update(buffer, 0, len);
            fos.write(plainbuffer);
            fos.flush();
        }

        plainbuffer = cipher.doFinal();
        fos.write(plainbuffer);
        fos.flush();

        if (fis != null)
            fis.close();
        if (fos != null)
            fos.close();
    }

    public static void main(String[] args) {
        try{
            //descryptionFile("/home/liyang/dev/vmware/Shared/Picture/event_video/trailer_encrpty.mp4", "/home/liyang/dev/vmware/Shared/Picture/event_video/out_java.mp4", "e388043e7f95a7550e28bffa27ac1df7");

            String md5 = DigestUtils.md5Hex(new FileInputStream("test.txt"));
            System.out.println("md5: "+md5);
        }catch (Exception e){
            System.out.println(e);
        }
    }
}
