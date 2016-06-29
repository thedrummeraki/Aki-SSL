package pkcs7;

import attributes.AttributeSet;
import tools.BashReader;
import tools.FileReader;
import tools.FileWriter;
import tools.Logger;
import x509.*;

/**
 * Created by aakintol on 28/06/16.
 */

import java.io.File;
import java.util.ArrayList;

import static x509.FileType.PEM;

public class PKCS7 implements Signable, Dumpable {

    private static final String[] DIGITS = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"};
    private static final String[] HEX_LETTERS = {"A", "B", "C", "D", "E", "F"};
    private static final String[] LETTERS = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};
    private FileType type;

    private ArrayList<File> tempFiles;

    private String filename;
    private String contents;
    private AttributeSet signedAttributes;
    private boolean isEnveloped;
    private boolean isSigned;
    private byte[] envelopedData;
    private byte[] signedData;
    private Certificate certificate;
    private Certificate certSigner;
    private PrivateKey privateKeySigner;


    public PKCS7(String rawData, boolean addHeaders) {
        String header = "";
        String footer = "";
        if (addHeaders) {
            header = "-----BEGIN PKCS7-----";
            footer = "-----END PKCS7-----";
        }
        this.contents = String.format("%s%s%s", header, rawData, footer);
        this.type = PEM;
    }

    public void setSigner(Certificate certSigner) {
        this.certSigner = certSigner;
    }

    public void setCertificate(String buff) throws CertificateException {
        this.certificate = Certificate.loadCertificateFromBuffer(buff);
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public void setCertSigner(Certificate signer) {
        this.certSigner = signer;
    }

    public void setPrivateKeySigner(PrivateKey privateKeySigner) {
        this.privateKeySigner = privateKeySigner;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public void createFilename(int length, boolean hex) {
        this.filename = FileWriter.dumpFilename(length, hex, getFileExtension());
    }

    public String getFileExtension() {
        switch (type.name()) {
            case "PEM": return ".pem";
            case "BER": return ".ber";
            case "CER": return ".cer";
            case "DER": return ".der";
            case "TEXT": return ".txt";
            default: return ".pem";
        }
    }

    public String getFilename() {
        return getFilename(true);
    }

    public String getFilename(boolean fullFilename) {
        return fullFilename ? filename + getFileExtension() : filename;
    }

    public void createFilename() {
        createFilename(20, true);
    }

    public boolean sign(Certificate signer) throws PKCS7Exception {
        this.certSigner = signer;
        return this.sign();
    }

    @Override
    public boolean sign() throws PKCS7Exception {
        if (this.certSigner == null) {
            throw new PKCS7Exception("You need to specify a signer!");
        }
        if (this.privateKeySigner == null) {
            if (this.certSigner.isSelfSigned()) {
                this.privateKeySigner = this.certSigner.getPrivateKey();
            }
            if (this.privateKeySigner == null) {
                throw new PKCS7Exception("You need to specify a private key!");
            }
        }
        if (this.certSigner.getBlob() == null) {
            throw new PKCS7Exception("It appears your certificate signer is empty");
        }
        if (isSigned && signedData != null) {
            // no need to sign it twice
            return true;
        }
        // Signs the raw data of PKCS7
        // Create a temp file that will hold the raw data.
        File tempRawData = new File("tmp/temp-"+getFilename());
        if (!FileWriter.write(this.contents, tempRawData.getAbsolutePath())) {
            throw new PKCS7Exception("Couldn't write the data to a temp file.");
        }
        addTempFile(tempRawData);

        //Create a temp file that will contain the signer
        File tempSignerBlob = new File("tmp/temp-"+getFilename(false)+".signer");
        if (!FileWriter.write(this.certSigner.getBlob(), tempSignerBlob.getAbsolutePath())) {
            throw new PKCS7Exception("Couldn't write the signer's blob of data to the file.");
        }
        addTempFile(tempSignerBlob);

        //Create a temp file that will contain the private key
        File tempKey = new File("tmp/temp-"+getFilename(false)+".key");
        Logger.debug("PKCS7", "Trying to write to the file.");
        if (!FileWriter.write(this.privateKeySigner.dumpPEM(this.certSigner.getSubject()), tempKey.getAbsolutePath())) {
            throw new PKCS7Exception("Couldn't write the signer's private key to the file.");
        }
        addTempFile(tempKey);

        String outFile = "temp-"+getFilename(false)+".signed";

        //How would we sign the contents?
        String[] args = {"openssl", "cms", "-sign", "-in", tempRawData.getAbsolutePath(), "-out", outFile,
                    "-signer", tempSignerBlob.getAbsolutePath(), "-inkey", tempKey.getAbsolutePath()};

        BashReader bashReader = BashReader.read(args);
        if (bashReader == null || bashReader.getExitValue() != 0) {
            if (bashReader == null) {
                throw new PKCS7Exception("The command \" \" + BashReader.toSingleString(args) + \"\" failed (null).");
            }
            throw new PKCS7Exception("The command \" " + BashReader.toSingleString(args) + "\" failed - " + bashReader.getOutput() + " ("+bashReader.getExitValue()+")");
        }

        // Now we have a file with signed data.
        this.signedData = BashReader.toSingleString(FileReader.getLines(outFile)).getBytes();

        if (cleanTempFiles()) {
            Logger.debug("Temp files all cleaned up.");
        } else {
            Logger.debug("Temp files NOT cleaned up (all or some).");
        }
        return isSigned;
    }

    @Override
    public byte[] dumpDER() {
        // Convert the blob of data to a DER contents
        if (contents == null) {
            return null;
        }
        return new byte[0];
    }

    @Override
    public String dumpPEM() {
        return contents;
    }

    public String getSignedDataAsString() {
        if (signedData == null) {
            return null;
        }
        return new String(signedData);
    }

    public FileType getType() {
        return type;
    }

    public boolean isSigned() {
        return isSigned;
    }

    public boolean isEnveloped() {
        return isEnveloped;
    }

    private void addTempFile(File tempFile) {
        if (tempFiles == null) {
            tempFiles = new ArrayList<>();
        }
        tempFiles.add(tempFile);
    }

    private boolean cleanTempFiles() {
        if (tempFiles == null || tempFiles.isEmpty()) {
            return true;
        }
        boolean ok = true;
        for (File file : tempFiles) {
            if (!file.delete()) {
                ok = false;
            }
        }
        return ok;
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
        PKCS7 pkcs7 = new PKCS7(rawData, false);
        pkcs7.createFilename();
        try {
            pkcs7.sign(Certificate.loadCertificateFromFile("/home/aakintol/Desktop/tester-cert.pem"));
            System.out.print(pkcs7.getSignedDataAsString());
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }

}
