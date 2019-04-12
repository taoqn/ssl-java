package rootCA;

import com.sun.deploy.security.X509DeployKeyManager;
import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinNT;

import javax.net.ssl.X509KeyManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Enumeration;
import java.util.Iterator;

public class CA {

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

//        KeyStore ks = KeyStore.getInstance("Windows-MY");
//        ks.load(null, null) ;
//        Enumeration en = ks.aliases() ;
//        while (en.hasMoreElements()) {
//            String aliasKey = (String) en.nextElement();
//            Certificate c = ks.getCertificate(aliasKey);
//            System.out.println("---> alias : " + aliasKey);
////            if (ks.isKeyEntry(aliasKey)) {
////                Certificate[] chain = ks.getCertificateChain(aliasKey);
////                for (Certificate cert : chain) {
////                    System.out.println(cert);
////                }
////            }
//            System.out.println("---> alias : " + c.getEncoded());
//        }

//        NativeLibrary cryptUI = NativeLibrary.getInstance("Cryptui");
//        NativeLibrary crypt32 = NativeLibrary.getInstance("Crypt32");
//
//        Function functionCertOpenSystemStore = crypt32.getFunction("CertOpenSystemStoreA");
//        Object[] argsCertOpenSystemStore = new Object[] { 0, "MY"};
//        WinNT.HANDLE h = (WinNT.HANDLE) functionCertOpenSystemStore.invoke(WinNT.HANDLE.class, argsCertOpenSystemStore);
//
//        Function functionCryptUIDlgSelectCertificateFromStore = cryptUI.getFunction("CryptUIDlgSelectCertificateFromStore");
//        System.out.println(functionCryptUIDlgSelectCertificateFromStore.getName());
//        Object[] argsCryptUIDlgSelectCertificateFromStore = new Object[] { h, 0, 0, 0, 16, 0, 0};
//        Pointer ptrCertContext = (Pointer) functionCryptUIDlgSelectCertificateFromStore.invoke(Pointer.class, argsCryptUIDlgSelectCertificateFromStore);

//        Function functionCertGetNameString = crypt32.getFunction("CertGetNameStringW");
//        char[] ptrName = new char[128];
//        Object[] argsCertGetNameString = new Object[] { ptrCertContext, 5, 0, 0, ptrName, 128};
//        functionCertGetNameString.invoke(argsCertGetNameString);
//        System.out.println("Selected certificate is " + new String(ptrName));
//
//        Function functionCertFreeCertificateContext = crypt32.getFunction("CertFreeCertificateContext");
//        Object[] argsCertFreeCertificateContext = new Object[] { ptrCertContext};
//        functionCertFreeCertificateContext.invoke(argsCertFreeCertificateContext);
//
//        Function functionCertCloseStore = crypt32.getFunction("CertCloseStore");
//        Object[] argsCertCloseStore = new Object[] { h, 0};
//        functionCertCloseStore.invoke(argsCertCloseStore);



        NativeLibrary cryptUI = NativeLibrary.getInstance("Cryptui");
        NativeLibrary crypt32 = NativeLibrary.getInstance("Crypt32");

        Function functionCertOpenSystemStore = crypt32.getFunction("CertFindCertificateInStore");
        Object[] argsCertOpenSystemStore = new Object[] { 0, "X509_ASN_ENCODING", };
        WinNT.HANDLE h = (WinNT.HANDLE) functionCertOpenSystemStore.invoke(WinNT.HANDLE.class, argsCertOpenSystemStore);

        Function functionCryptUIDlgSelectCertificateFromStore = cryptUI.getFunction("CryptUIDlgSelectCertificateFromStore");
        System.out.println(functionCryptUIDlgSelectCertificateFromStore.getName());
        Object[] argsCryptUIDlgSelectCertificateFromStore = new Object[] { h, 0, 0, 0, 16, 0, 0};
        Pointer ptrCertContext = (Pointer) functionCryptUIDlgSelectCertificateFromStore.invoke(Pointer.class, argsCryptUIDlgSelectCertificateFromStore);


    }
}