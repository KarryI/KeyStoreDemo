package com.jeejio.lib;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

public class MyClass {
    public static void main(String[] args){
        String subject = "CN=Jeejio sw,OU=Software,O=Jeejio,L=Beijing,ST=Beijing,C=CN";
        String issuerStr = subject;
        String subjectStr = subject;
        String certificateCRL  = "https://gitbook.cn";
        String ALIAS = "jeejio.device";
        String PASSWORD = "123456";
        MyClass myClass = new MyClass();
        String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLS6yW5Ofl1z+2\n" +
                "pkhCrnGn4Eld4sZqn/gqItTrschALQN5vF6eDS4NOqa+e8slydqpnVnjgs3m0rW6\n" +
                "+EdzClCyR/ICDPAdsFe3X5GXBiJrYMc7WQNcFNUYBMm5R9JKRLQCXrmtNacuvo3U\n" +
                "tttzYNbJYUvlG29YGsdFnePOY3Zm0aj5o6qn9oOY5Po30fAKjd/xEeE5GoTw/RbI\n" +
                "SFsx93GPUfcKf+YFU79lheT/ZGRlBpETPmLr5oVvVYR96ZnYhGDDY4nUhjNT0y63\n" +
                "MP4IWzNheAWXhLPP12PkID9MUPX/6Rp2NQfxspEf6u1Hp/r46YDBwu2J7Ff1RAq4\n" +
                "Z6PD1lfBAgMBAAECggEAIg6MXD7+xldX+h5DLsCQk8IUKGFMQiKIbW6mYtHGrVGd\n" +
                "KnCvHSUyGM9BjdmpP6xgMFgG7gFEwy17elYLii8pM6Sv2z4Vn7OiDjs5ZaaGb5yn\n" +
                "475WvL9Ur5Blxt9MUFrQGTGLQ4QgfMk5c3AqtVp8wQHGuBvvfEAIMBZySmoJNNIQ\n" +
                "LkWXyqJO9jv3k1Q5oNcK4/OgswkHXBP9P+C/cIDaVYGTit1csNLgapWUPoCd6QLb\n" +
                "311L9AimePLbdUNRxtBYCGxv3QwPoyTRPn7HGX5Ubr6H9JdtLiZRJwDtmTAoe8l0\n" +
                "PhpVDKmM6GoLUlQ1wbqnAl0Kc4xldzfF136IzZaBDQKBgQD1A24Dun1bEfsU5DjX\n" +
                "Gqs69zEpJ/98knxveC0tQMusXr+Bh0dyGCtH2HImEo9oI+wCIQZ7Hhx/r6y0Fy/s\n" +
                "zwH7Ra6WGMTLOEwVvPIO/iEN8nUfWpIWpk59Iu5gcu5HKoFHuGQdBBi6SL1d+cNc\n" +
                "DkrrwuJXG5MX9ULfiZORuaCvrwKBgQDUaVr7QsPyNV/6j8jULEjfnnxGxrTk2sCD\n" +
                "CM1Wz7Q0CBJ4NQRHerolxErfK8S5P82pLEBE2vMGkvnU/fFbSKZO/s2vWyFvNuo1\n" +
                "ylQRkQOb4i0QXpXo7gp336snG0kiiPkcvMbXUYZPNHiruCMn1jUT3UamyTgvkgL2\n" +
                "dNdf5K9bjwKBgQC2yflAhNfSooZ8HoudRsMqOZKOjs2XJT36d2DU2vtYPFOJEeCm\n" +
                "aQuZDQyUBNLCMdJ4ACVyopNGW0xwCsBxXjqvOFw4lH/00KpKqWy47LTCT/k7C/nj\n" +
                "Ne1mhDHs+LF1nGtYk2L1FsJP78Z/Hr+1pOAWJY1wyRyjChH67QuP8znC9wKBgG7x\n" +
                "UDnoF1wMkMLYErbvImjZ6GM3KghWUTKfiFCNT7vVc4AhgMisy0kqi0ihHbD8KDjy\n" +
                "CedszH5kieS7djKNcX/VCi1K1d22uwG5WcuLCG2E5rCkFnyAyCrwQf68+6f0Dtj5\n" +
                "qImR5Sq9Z0GZfZMzCKoFav92HciK5M1BHbTSRtz1AoGAQQh/pfUOY07+yMZtIL5U\n" +
                "vJ/gi4HqMmb1nt1H88Fs3uKAA58zSFyRMC0Zokg9S4VXBAeX8YbUQkiQJPa+0k/H\n" +
                "HX5EX6m5C5pPPXhHKcLkZ6W9nNPBbbEFiHOz7ls0XQXrsgDcBMZSeQzs4TFmMziy\n" +
                "RL9ejMJql6aUn33RdbWBJg8=";
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy0usluTn5dc/tqZIQq5x\n" +
                "p+BJXeLGap/4KiLU67HIQC0Debxeng0uDTqmvnvLJcnaqZ1Z44LN5tK1uvhHcwpQ\n" +
                "skfyAgzwHbBXt1+RlwYia2DHO1kDXBTVGATJuUfSSkS0Al65rTWnLr6N1Lbbc2DW\n" +
                "yWFL5RtvWBrHRZ3jzmN2ZtGo+aOqp/aDmOT6N9HwCo3f8RHhORqE8P0WyEhbMfdx\n" +
                "j1H3Cn/mBVO/ZYXk/2RkZQaREz5i6+aFb1WEfemZ2IRgw2OJ1IYzU9MutzD+CFsz\n" +
                "YXgFl4Szz9dj5CA/TFD1/+kadjUH8bKRH+rtR6f6+OmAwcLtiexX9UQKuGejw9ZX\n" +
                "wQIDAQAB";
        String data = "{\"vpnConf\":\"client\\r\\ndev tun\\r\\nproto tcp\\r\\n# lport 1198\\r\\nnobind\\r\\nresolv-retry infinite\\r\\npersist-key\\r\\npersist-tun\\r\\n\\r\\n\\r\\ncipher AES-256-CBC\\r\\nremote-cert-tls server\\r\\ncomp-lzo\\r\\nverb 3\",\"vpnCrt\":\"-----BEGIN CERTIFICATE-----\\nMIICMzCCAZSgAwIBAgIJAIcftJEnAKikMAoGCCqGSM49BAMCMBYxFDASBgNVBAMM\\nC0Vhc3ktUlNBIENBMCAXDTE5MTAyNTAxMzgyNFoYDzIxMTkxMDAxMDEzODI0WjAW\\nMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAE\\nAcv3NvSUEc6M3WGayt9aJeIMyDtdBN69oteVUBnktmPt+HPBoz7LtW5qfpPUXiqY\\nWMzctKqtJkPAy0WB0AEcCPYyAbc88B970hD9KxBWKaInOdolROXL13JhGgVW9ldJ\\nRtHZi/wgVFOx1AoFRnUZpZjhUGv36zs+yyyf/wsZetjxnZVOo4GFMIGCMB0GA1Ud\\nDgQWBBQF1C/kEs23qIYg03NBX36YV3rvazBGBgNVHSMEPzA9gBQF1C/kEs23qIYg\\n03NBX36YV3rva6EapBgwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0GCCQCHH7SRJwCo\\npDAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjAKBggqhkjOPQQDAgOBjAAwgYgC\\nQgHXDcHr6x+kfwXkb3krcCSdnF8uNIVjqrD//qrx6kuPTfwaQ9t2RN0GMa/FFhXC\\nkGj1ifUNPCGD0R7M9+gaFkSV6gJCAJSsMa1UPKIKNtw25tOirAoL1zIMg6nwD8Qr\\nMdN/aS667cX0IQwCL/rIQNx6MTCEfFuR9nckg5pvpX7OwxCafM3o\\n-----END CERTIFICATE-----\",\"vpnIp\":\"10.10.11.15\",\"vpnNetmask\":\"255.255.252.0\",\"vpnPort\":1198,\"vpnPsw\":\"mNv6MH8%/#y\",\"vpnRes\":\"client\\r\\ndev tun\\r\\nproto tcp\\r\\n# lport 1198\\r\\nnobind\\r\\nresolv-retry infinite\\r\\npersist-key\\r\\npersist-tun\\r\\n\\r\\n\\r\\ncipher AES-256-CBC\\r\\nremote-cert-tls server\\r\\ncomp-lzo\\r\\nverb 3\\n\\n\\n\\nremote 10.10.11.15 1198\\n<ca>\\n-----BEGIN CERTIFICATE-----\\nMIICMzCCAZSgAwIBAgIJAIcftJEnAKikMAoGCCqGSM49BAMCMBYxFDASBgNVBAMM\\nC0Vhc3ktUlNBIENBMCAXDTE5MTAyNTAxMzgyNFoYDzIxMTkxMDAxMDEzODI0WjAW\\nMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAE\\nAcv3NvSUEc6M3WGayt9aJeIMyDtdBN69oteVUBnktmPt+HPBoz7LtW5qfpPUXiqY\\nWMzctKqtJkPAy0WB0AEcCPYyAbc88B970hD9KxBWKaInOdolROXL13JhGgVW9ldJ\\nRtHZi/wgVFOx1AoFRnUZpZjhUGv36zs+yyyf/wsZetjxnZVOo4GFMIGCMB0GA1Ud\\nDgQWBBQF1C/kEs23qIYg03NBX36YV3rvazBGBgNVHSMEPzA9gBQF1C/kEs23qIYg\\n03NBX36YV3rva6EapBgwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0GCCQCHH7SRJwCo\\npDAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjAKBggqhkjOPQQDAgOBjAAwgYgC\\nQgHXDcHr6x+kfwXkb3krcCSdnF8uNIVjqrD//qrx6kuPTfwaQ9t2RN0GMa/FFhXC\\nkGj1ifUNPCGD0R7M9+gaFkSV6gJCAJSsMa1UPKIKNtw25tOirAoL1zIMg6nwD8Qr\\nMdN/aS667cX0IQwCL/rIQNx6MTCEfFuR9nckg5pvpX7OwxCafM3o\\n-----END CERTIFICATE-----\\n</ca>\",\"vpnUser\":\"01271100000200000001\"}";


//        myClass.createCert(ALIAS,PASSWORD, issuerStr, subjectStr, certificateCRL);
        try {
            //String publicText = RSA.decrypt(data, RSA.getPrivateKey(privateKey));
            //System.out.println("keyStoreData= "+publicText);
            String en_data = RSA.encrypt(data,RSA.getPublicKey(publicKey));
            System.out.println("en_data= "+en_data);
        }catch (Exception e){
            e.printStackTrace();
            System.out.println("error");
        }
    }
    /**
     * @param password  密码
     * @param issuerStr 颁发机构信息
     * @param subjectStr 使用者信息
     * @param certificateCRL 颁发地址
     * @return
     */
    private Map<String, byte[]> createCert(String alias, String password,
                                           String issuerStr, String subjectStr, String certificateCRL) {
        Map<String, byte[]> result = new HashMap<String, byte[]>();
        ByteArrayOutputStream out = null;
        try {
            //  生成JKS证书
            //  KeyStore mKeyStore = KeyStore.getInstance("JKS");
            //  标志生成PKCS12证书
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            KeyPair keyPair = getKey();
            //  issuer与 subject相同的证书就是CA证书
            Certificate cert = generateCertificateV3(issuerStr, subjectStr,  keyPair, result, certificateCRL, null);
            // cretkey随便写，标识别名
            keyStore.setKeyEntry(alias,  keyPair.getPrivate(),  password.toCharArray(),  new Certificate[] { cert });
            out = new ByteArrayOutputStream();
            cert.verify(keyPair.getPublic());
            keyStore.store(out, password.toCharArray());
            byte[] keyStoreData = out.toByteArray();
            result.put("keyStoreData", keyStoreData);
            System.out.println("keyStoreData= "+new String(Base64.encode(keyStoreData, Base64.DEFAULT)));
            writeExternal("/home/liyang/dev/Cert/P12/device.p12",keyStoreData);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                }
            }
        }
        return result;
    }

    private KeyPair getKey() throws NoSuchAlgorithmException {
        // 密钥对 生成器，RSA算法 生成的  提供者是 BouncyCastle
        KeyPairGenerator generator = null;
        KeyPair keyPair = null;
        generator = KeyPairGenerator.getInstance("RSA",new BouncyCastleProvider());
        generator.initialize(2048);  // 密钥长度 2048
        // 证书中的密钥 公钥和私钥
        keyPair = generator.generateKeyPair();
        return keyPair;
    }

    /**
     * @param issuerStr
     * @param subjectStr
     * @param keyPair
     * @param result
     * @param certificateCRL
     * @param extensions
     * @return
     */
    public Certificate generateCertificateV3(String issuerStr, String subjectStr, KeyPair keyPair, Map<String, byte[]> result,
                                             String certificateCRL, List<Extension> extensions) {
        ByteArrayInputStream bout = null;
        X509Certificate cert = null;
        try {
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            Date notBefore = new Date();
            Calendar rightNow = Calendar.getInstance();
            rightNow.setTime(notBefore);
            // 日期加10年
            rightNow.add(Calendar.YEAR, 10);
            Date notAfter = rightNow.getTime();
            // 证书序列号
            BigInteger serial = BigInteger.probablePrime(256, new Random());
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new X500Name(issuerStr), serial, notBefore, notAfter,new X500Name(subjectStr), publicKey);
            JcaContentSignerBuilder jBuilder = new JcaContentSignerBuilder( "SHA1withRSA");
            SecureRandom secureRandom = new SecureRandom();
            jBuilder.setSecureRandom(secureRandom);
            ContentSigner singer = jBuilder.setProvider(  new BouncyCastleProvider()).build(privateKey);
            // 分发点
            ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier( "2.5.29.31");
            GeneralName generalName = new GeneralName( GeneralName.uniformResourceIdentifier, certificateCRL);
            GeneralNames seneralNames = new GeneralNames(generalName);
            DistributionPointName distributionPoint = new DistributionPointName( seneralNames);
            DistributionPoint[] points = new DistributionPoint[1];
            points[0] = new DistributionPoint(distributionPoint, null, null);
            CRLDistPoint cRLDistPoint = new CRLDistPoint(points);
            builder.addExtension(cRLDistributionPoints, true, cRLDistPoint);
            // 用途
            ASN1ObjectIdentifier keyUsage = new ASN1ObjectIdentifier( "2.5.29.15");
            // | KeyUsage.nonRepudiation | KeyUsage.keyCertSign
            builder.addExtension(keyUsage, true, new KeyUsage( KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            // 基本限制 X509Extension.java
            ASN1ObjectIdentifier basicConstraints = new ASN1ObjectIdentifier("2.5.29.19");
            builder.addExtension(basicConstraints, true, new BasicConstraints(true));
            // privKey:使用自己的私钥进行签名，CA证书
            if (extensions != null){
                for (Extension ext : extensions) {
                    builder.addExtension(
                            new ASN1ObjectIdentifier(ext.getOid()),
                            ext.isCritical(),
                            ASN1Primitive.fromByteArray(ext.getValue()));
                }
            }
            X509CertificateHolder holder = builder.build(singer);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            bout = new ByteArrayInputStream(holder.toASN1Structure() .getEncoded());
            cert = (X509Certificate) cf.generateCertificate(bout);
            byte[] certBuf = holder.getEncoded();
            SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
            // 证书数据
            result.put("certificateData", certBuf);
//            Log.d(TAG,"certificateData= "+new String(Base64.encode(certBuf, Base64.DEFAULT)));
            //公钥
            result.put("publicKey", publicKey.getEncoded());
            System.out.println("publicKey= "+new String(Base64.encode(publicKey.getEncoded(), Base64.DEFAULT)));
            //私钥
            result.put("privateKey", privateKey.getEncoded());
            System.out.println("privateKey= "+new String(Base64.encode(privateKey.getEncoded(), Base64.DEFAULT)));
            //证书有效开始时间
            result.put("notBefore", format.format(notBefore).getBytes("utf-8"));
//            Log.d(TAG,"notBefore= "+new String(Base64.encode(format.format(notBefore).getBytes("utf-8"), Base64.DEFAULT)));
            //证书有效结束时间
            result.put("notAfter", format.format(notAfter).getBytes("utf-8"));
//            Log.d(TAG,"notAfter= "+new String(Base64.encode(format.format(notAfter).getBytes("utf-8"), Base64.DEFAULT)));
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (bout != null) {
                try {
                    bout.close();
                } catch (IOException e) {
                }
            }
        }
        return cert;
    }

    public static void writeExternal(String path, byte[] bytes) {
        FileOutputStream outputStream = null;
        try {
            outputStream = new FileOutputStream(path);
            outputStream.write(bytes);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e){
            e.printStackTrace();
        } finally {
            try {
                outputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
