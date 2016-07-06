package pkcs7;

import tools.BashReader;
import tools.FileReader;
import tools.FileWriter;
import tools.Logger;
import utils.VerifyUtils;
import x509.*;

/**
 * Created by aakintol on 28/06/16.
 */

import java.io.File;

import static x509.FileType.PEM;

public class PKCS7 extends Signable {

    private boolean isEnveloped;
    private boolean isEncrypted;
    private byte[] encryptedData;
    private Certificate certificate;


    public PKCS7(String rawData, boolean addHeaders) {
        String header = "";
        String footer = "";
        if (addHeaders) {
            header = "-----BEGIN PKCS7-----";
            footer = "-----END PKCS7-----";
        }
        this.setContents(String.format("%s%s%s", header, rawData, footer));
        this.setType(PEM);
    }

    public void setCertificate(String buff) throws CertificateException {
        this.certificate = Certificate.loadCertificateFromBuffer(buff);
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public String getEncryptedDataAsString() {
        if (encryptedData == null) {
            return null;
        }
        return new String(encryptedData);
    }

    public boolean isEnveloped() {
        return isEnveloped;
    }

    public boolean isEncrypted() {
        return isEncrypted;
    }

    public boolean sign(Certificate signer) throws PKCS7Exception {
        this.setCertSigner(signer);
        try {
            return this.sign(signer);
        } catch (SignatureException e) {
            throw new PKCS7Exception(e);
        }
    }

    public boolean encrypt() throws CertificateException {
        if (!isSigned || getSignedDataDER() == null || getSignedDataPEM() == null) {
            throw new CertificateException("Please sign the PKCS7 first with a signer and its private key.");
        }

        // As the first statement of this methods implies it, the encryption process come right after the signing process
        // This means the encrypt should be very similar to the signing process, and thus easier to understand

        // This file should exist, so get its contents or dump the signed data if the file is not there.
        File tempSigned = new File("tmp/temp-"+getFilename(false)+".signed");
        File tempEnc = new File("tmp/temp-"+getFilename(false)+".encrypted");
        if (!tempSigned.exists()) {
            FileWriter.write(getDERSignedDataAsString(), tempSigned.getPath());
        }
        addTempFile(tempSigned);

        //Create a temp file that will contain the signer
        File tempSignerBlob = new File("tmp/temp-"+getFilename(false)+".signer");
        if (!FileWriter.write(this.getCertSigner().getBlob(), tempSignerBlob.getAbsolutePath())) {
            throw new PKCS7Exception("Couldn't write the signer's blob of data to the file.");
        }
        addTempFile(tempSignerBlob);

        String[] args = {"openssl", "cms", "-encrypt", "-in", tempSigned.getPath(), "-out", tempEnc.getPath(), tempSignerBlob.getPath()};

        BashReader bashReader = BashReader.read(args);
        if (bashReader == null || bashReader.getExitValue() != 0) {
            if (bashReader == null) {
                throw new PKCS7Exception("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new PKCS7Exception("The command \"" + BashReader.toSingleString(args) + "\" failed - " + bashReader.getOutput() + " ("+bashReader.getExitValue()+")");
        }

        // Now we have a file with encrypted data!
        this.encryptedData = BashReader.toSingleString(FileReader.getLines(tempEnc)).trim().getBytes();
        this.isEncrypted = true;

        if (cleanTempFiles()) {
            Logger.debug("PKCS7", "PKCS7.encrypt(): Temp files all cleaned up.");
        } else {
            Logger.debug("PKCS7", "PKCS7.encrypt(): Temp files NOT cleaned up (all or some).");
        }

        return isEncrypted;
    }

    public boolean signAndEncrypt() throws CertificateException {
        return sign() && encrypt();
    }

    @Override
    public boolean sign() throws CertificateException {
        try {
            return super.sign();
        } catch (SignatureException e) {
            throw new PKCS7Exception(e);
        }
    }

    public void verifySignature(Certificate caCert) throws PKCS7Exception {

    }

    public static void main(String[] args) {
        String rawData = "-----BEGIN PKCS7-----\n" +
                "MIIGugYJKoZIhvcNAQcCoIIGqzCCBqcCAQExDjAMBggqhkiG9w0CBQUAMIIDIQYJ\n" +
                "KoZIhvcNAQcBoIIDEgSCAw4wggMKBgkqhkiG9w0BBwOgggL7MIIC9wIBADGCAUow\n" +
                "ggFGAgEAMC4wKTELMAkGA1UEChMCcWExGjAYBgNVBAMTEVN0VmluY2VudFFBQ0Ey\n" +
                "MDExAgEBMA0GCSqGSIb3DQEBAQUABIIBAJAuX2pGfDb4QvwQh8KHmtoeZ4Yawkcc\n" +
                "qihpBVHoLfw8X1JGYIp1QFc9SHYuesv5G3sxN1RxVwrDAZo+aaGWWwbCLjvmlFAr\n" +
                "SO5cBXYtJOvnD9DfNlRC++1miOmi2slzbxC7rq7DNo+uaC6YEE/Np/uFmoftLltC\n" +
                "V6BOgzXWCnDOjTqyuVRyZcjJ5fOJwpwbuAn5jbiEiSQLMUc7hhHdxC0sdlVYwrtO\n" +
                "Yjh/H9LpoO+H1LacTp41XBpK9QBgB80PTtkRzjlMInmjATtdaWYhPdGJh2s5z0bQ\n" +
                "mJc8cd2sIN7LAmV/r7I6dGZZkzSAAWOfUxNWRzGHvdITw24G28kZCeQwggGiBgkq\n" +
                "hkiG9w0BBwEwEQYFKw4DAgcECMa+/NEt+BAtgIIBgEYGsXOk72sGavghfEh80pJO\n" +
                "KNRxgfI99AzhQH/C+HA3yGU8WH3GUPCCIH/UJ3PxMZOgiAhJytucVrboVqwvvqN8\n" +
                "BJHsbj702MPLLwvfD3dgz5CjhXRwd+nYVCIihyTWx2SOqFjBhkWayLTbgXga/eRg\n" +
                "HLV+Pr87rt+6aIiuOrRpfuToxYaeBqAKClj/iJYeRMOCmSxRzx4OPsktg2f06EIw\n" +
                "W6sWikK53GvIocCXpCiymwiKChDYn5iingh4zkcKVq78ZtuzD9JFhha5BRqueCve\n" +
                "iModreVI9WJpc0rLjHRaRafLAsic2zxylxR3ycm/TNQ6aU1XXYmY24n3u9pRHH+k\n" +
                "kxQvzhtt/pw5mwqnTW1Y9J8wMRnW1wPa7uZuv6QxZymfphJWBTCoek5u+pVHCYwf\n" +
                "TGaP0bh8K3Ylsqwi6bIBaBc1bNkLQ4pRQXa70tU61lL+LuCC3f3auimMdUjWr1QP\n" +
                "LtRr8zV9AbpbyNVqfDiGWYX4Xu9XFAxghbu2oKJbSKCCAcEwggG9MIIBJqADAgEC\n" +
                "AiBDMDZGMkVGNjg4Mjc5NUJDQzgyODkxMTkxMkYzRjcyODANBgkqhkiG9w0BAQQF\n" +
                "ADAVMRMwEQYDVQQDEwoxMjcuMC4xLjEwMB4XDTE2MDYyNzE4MDExMFoXDTE2MDcw\n" +
                "MzIwMDExMFowFTETMBEGA1UEAxMKMTI3LjAuMS4xMDCBnzANBgkqhkiG9w0BAQEF\n" +
                "AAOBjQAwgYkCgYEAmlixAXWAbhwCjZN1hRosDwTPNxh4SzoscCAU7UPZk3CDQ10z\n" +
                "YF5em8Ui4xTjcwWnlUwxsWBD64Pai3WAiqBhuB6AVw5rFTVDV4SMDdU+SLuniRZp\n" +
                "LK3BXiFiqHQp5Z7fs+OxDzSGpWR0Y5JQUOCfd6RyJ2D7oBY5L89b4uPbs98CAwEA\n" +
                "ATANBgkqhkiG9w0BAQQFAAOBgQBTx85iXRnNlP9Ojl73OB2K2fK+Yzfo+r3Hf51E\n" +
                "g7EHP1eWYVi59/QYdN+5WcgViQWbgAygLHqQQa/vppmklp9ZnY2mNLtPIwAKE2sf\n" +
                "8yXLW6YNE+T4H0lzY8DLBPjR2NHvboC9USuAEl5/0cP1tp7AnXAodyrQ9USsoZ2c\n" +
                "r3KjpjGCAaYwggGiAgEBMDkwFTETMBEGA1UEAxMKMTI3LjAuMS4xMAIgQzA2RjJF\n" +
                "RjY4ODI3OTVCQ0M4Mjg5MTE5MTJGM0Y3MjgwDAYIKoZIhvcNAgUFAKCBwTASBgpg\n" +
                "hkgBhvhFAQkCMQQTAjE5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI\n" +
                "hvcNAQkFMQ8XDTE2MDYyNzE4MDExMFowHwYJKoZIhvcNAQkEMRIEEE7F5LZ/EG9Z\n" +
                "lkAsVchtrhwwIAYKYIZIAYb4RQEJBTESBBD6vHMHXuym8XD6AqjAlTUyMDAGCmCG\n" +
                "SAGG+EUBCQcxIhMgQzA2RjJFRjY4ODI3OTVCQ0M4Mjg5MTE5MTJGM0Y3MjgwDQYJ\n" +
                "KoZIhvcNAQEBBQAEgYBYpGW/8dKMHnED09/pkqr2FYTBSlVTIqAIN0ECHt+BmNW3\n" +
                "FhzL5AUEAaAcCf+fPuNgFUITOcM0YYGvzXD0vUrtrzfhSk2wFAU+olH/yYM+0mJ7\n" +
                "ZgVL5zy55NHa7XsrcIVs576RGA6czEoetftYGRykS8zU6SOKFumC86ojkBKeYw==\n" +
                "-----END PKCS7-----\n";
//        rawData = BashReader.toSingleString(FileReader.getLines("/home/aakintol/Downloads/cbn_dsa-cert.pem"));
//        Signable pkcs7 = new Signable();
//        pkcs7.setContents(rawData);
////        pkcs7.createFilename();
//        try {
//            Certificate signer = Certificate.loadCertificateFromFile("test-signer.pem");
//            PrivateKey privateKey = PrivateKey.loadPrivateKey(new File("test-key.key"));
//
//            pkcs7.setCertSigner(signer);
//            pkcs7.setPrivateKeySigner(privateKey);
//            pkcs7.sign();
//            int v = pkcs7.verify();
//            System.exit(v);
//            System.out.println(pkcs7.getDERSignedDataAsString());
//        } catch (CertificateException e) {
//            e.printStackTrace();
//            System.exit(1);
//        }

//        BashReader bashReader = BashReader.read("python", "hexdump", "-in", "verified.bin");
//        if (bashReader != null) {
//            System.out.println(bashReader.getExitValue());
//            System.out.println(bashReader.getOutput());
//        } else {
//            System.out.println("HMMM.");
//        }

        Signable signable = new Signable();
        Subject load;
        try {
            load = Subject.load("/C=CA/L=Ottawa/CN=cbnca");
        } catch (Exception e) {
            load = null;
        }

        signable.setContents(rawData);
        Logger.debug("set priv key + cert: "+VerifyUtils.setKeyAndSigner("test-key.key", "test-signer.pem", signable));
        signable.sign(null, null, null);
        Logger.debug("signed data: "+signable.getSignedDataPEM());

//        Logger.printOut(signable.getCertSigner().getBlob());
//        Logger.printOut(new String(signable.getPrivateKeySigner().dumpDER()));
//        Logger.printOut(signable.getPrivateKeySigner().dumpPEM());

//        Logger.debug("keygen: "+VerifyUtils.generateKey("rsa", 2048, new File("res/out.key"), new File("res/out.cert"), signable, load));
//
//        signable.setContents("valid contents.");
//        Logger.debug("sign: "+SignUtils.execOpenSSLCMSSign("sha1", true, false, false, signable));
//        Logger.debug("signed? "+signable.isSigned());
//        Logger.debug("locate sig pem: "+VerifyUtils.locateSignature("PEM", signable));
//        Logger.debug("locate sig der: "+VerifyUtils.locateSignature("DER", signable));
//        Logger.debug("pub key extraction: "+VerifyUtils.extractPublicKeyFromCertificate("pem", signable));
//        Logger.debug("asn1parse: "+SignUtils.execOpenSSLASN1Parse("DER", signable, false));
//        Logger.debug("extract rsa bin: "+VerifyUtils.extractBinaryRSAEncryptedHash("sha256", signable));
//        Hexdump hexReceiver = new Hexdump();
//        Logger.debug("hexdump: "+VerifyUtils.performHexdump("res/signed-sha256.bin", hexReceiver));
//        Logger.debug("hexdump result: "+hexReceiver.getDump());
//        Logger.debug("sig verif: "+VerifyUtils.verifySignature("res/signed-sha256.bin", "verified256.bin", signable));

//        VerifyUtils.locateSignature("PEM", signable);
//        try {
//            signable.setContents("HAHAHAHAHAHAH to sign.");
//            signable.sign();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        }

        try {
            Thread.sleep(5000);
            BashReader.read("rm", "-rf", "tmp/");
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

//        BashReader br = BashReader.read("openssl req -key out.key -new -x509 -days 365 -out out.cert -subj \"/CN=cbnca/C=CA/L=Ottawa\"");
//
//        Logger.debug(br != null ? br.getExitValue() + " : "+br.getOutput() : "NULL");

//        try {
//            String[] argv = {"openssl", "req", "-nodes", "-newkey", String.format("%s:%s", "rsa", 2048), "-keyout", "java.key", "-subj", "/C=CA/L=Ottawa/OU=CBN"};
//            BashReader br = BashReader.read(argv);
//            Logger.debug(br != null ? br.toString() : "NULL");
//            argv = new String[]{"openssl", "req", "-key", "java.key", "-new", "-x509", "-days", "365", "-out", "java.cert", "-subj", "/C=CA/L=Ottawa/OU=CBN"};
//            br = BashReader.read(argv);
//            Logger.debug(br != null ? br.toString() : "NULL");
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

    }
}
