package x509;

import tools.*;
import tools.FileReader;

import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by aakintol on 28/06/16.
 */
public class Certificate implements Dumpable {

    private int version;
    private long serialNumber;
    private Issuer issuer;
    private Date notBefore;
    private Date notAfter;
    private Subject subject;
    private PublicKey subjectPublicKey;
    private PrivateKey privateKey;
    private Extensions extensions;
    private String blob;

    private String filename;

    public Certificate(int version, long serialNumber, Issuer issuer, Date notBefore, Date notAfter,
        Subject subject, PublicKey subjectPublicKey, Extensions extensions) {
        this.version = version;
        this.serialNumber = serialNumber;
        this.issuer = issuer;
        this.notAfter = notAfter;
        this.notBefore = notBefore;
        this.subject = subject;
        this.subjectPublicKey = subjectPublicKey;
        this.extensions = extensions;
    }

    public Certificate() {
        version = -1;
        serialNumber = -1;
        issuer = null;
        notAfter = Calendar.getInstance().getTime();
        notBefore = Calendar.getInstance().getTime();
        subject = new Subject(null, null);
        subjectPublicKey = PublicKey.newInstance();
        extensions = new Extensions();
    }

    public Certificate setBlob(String blob) {
        this.blob = blob;
        return this;
    }

    public String getBlob() {
        if (blob == null) {

        }
        return blob;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setSubject(String o, String cn) {
        setSubject(new Subject(o, cn));
    }

    public Subject getSubject() {
        return subject;
    }

    public boolean isSelfSigned() {
        return isSelfSigned(true);
    }

    public boolean isSelfSigned(boolean openssl) {
        if (openssl) {
            BashReader br = BashReader.read("openssl", "x509", "-inform", "PEM", "-in", getFilename(), "-noout", "-subject");
            if (br == null) {
                return false;
            }
            String sub = br.getOutput();
            sub = sub.substring(9, sub.length()-1).trim();
//            Logger.debug("PKCS7", "Subject: "+sub);
            br = BashReader.read("openssl", "x509", "-inform", "PEM", "-in", getFilename(), "-noout", "-issuer");
            if (br == null) {
                return false;
            }
            String iss = br.getOutput();
            iss = iss.substring(8, iss.length()-1).trim();
//            Logger.debug("PKCS7", "Issuer: "+iss);
            return sub.length() == iss.length() && sub.equals(iss);
        }
        if (issuer != null && subject != null) {
            Logger.debug("PKCS7", "Subject: "+subject.getRawString()+"\nIssuer: "+issuer.getRawString());
            return issuer.equals(subject);
        }
        Logger.warn("PKCS7", "No issuer or/and subject provided.");
        return false;
    }

    public String getFilename() {
        if (filename == null) {

        }
        return filename;
    }

    @Override
    public byte[] dumpDER() {
        // Convert the blob to a DER contents
        if (blob == null) {
            return null;
        }
        return new byte[0];
    }

    @Override
    public String dumpPEM() {
        return blob;
    }

    public static Certificate loadCertificateFromFile(File file) throws CertificateException {
        return loadCertificateFromFile(file.getPath());
    }

    public static Certificate loadCertificateFromFile(String filename) throws CertificateException {
        if (filename == null) {
            throw new CertificateException("Filename cannot be null.");
        }
        File file = new File(filename);
        if (!file.exists()) {
            throw new CertificateException("Certificate at path " + filename + " does not exist.");
        }
        InputStream inputStream;
        try {
            inputStream = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new CertificateException(e.getClass() + " - " + e.getLocalizedMessage());
        }
        Certificate certificate = loadCertificateFromBuffer(inputStream);
        if (certificate != null) {
            // Getting the subject
            String[] args = {"openssl", "x509", "-inform", "PEM", "-in", filename, "-noout", "-subject"};
            String[] args2 = {"openssl", "x509", "-inform", "PEM", "-in", filename, "-noout", "-issuer"};
            BashReader read = BashReader.read(args);
            BashReader read2 = BashReader.read(args2);
            if (read != null) {
                String output = read.getOutput();
                if (output.startsWith("subject= ")) {
                    output = output.substring(9, output.length()-1);
                    certificate.subject = Subject.load(output);
                }
            }
            if (read2 != null) {
                String output = read2.getOutput();
                if (output.startsWith("issuer= ")) {
                    output = output.substring(8, output.length()-1);
                    certificate.issuer = Issuer.load(output);
                }
            }
            certificate.filename = filename;
            certificate.blob = BashReader.toSingleString(FileReader.getLines(filename));
        }
        return certificate;
    }

    public static Certificate loadCertificateFromBuffer(String buffer) throws CertificateException {
        InputStream stream = new ByteArrayInputStream(buffer.getBytes());
        Certificate certificate = loadCertificateFromBuffer(stream);
        if (certificate != null) {
            certificate = certificate.setBlob(buffer);
        }
        return certificate;
    }

    public static Certificate loadCertificateFromBuffer(InputStream buffer) throws CertificateException {
        try {
            java.security.cert.Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(buffer);
            X509Certificate x509Certificate = (X509Certificate) certificate;
            Certificate cert = new Certificate();
            cert.serialNumber = x509Certificate.getSerialNumber().longValue();
            cert.version = x509Certificate.getVersion();
            cert.notBefore = x509Certificate.getNotBefore();
            cert.notAfter = x509Certificate.getNotAfter();

            String pkAlg = x509Certificate.getPublicKey().getAlgorithm();
            String pkFor = x509Certificate.getPublicKey().getFormat();

            PrivateKey privateKey = PrivateKey.newInstance();
            privateKey.setAlgorithm(pkAlg);
            privateKey.setFormat(pkFor);
            privateKey.setDerContents(x509Certificate.getPublicKey().getEncoded());

            cert.privateKey = privateKey;

            return cert;
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String filename = "/home/aakintol/Desktop/StVincentQACA2011";
//        ArrayList<String> lines = FileReader.getLines(filename);
//        String buffer = "";
//        for (String line : lines)
//            buffer += line + "\n";
//        buffer = buffer.trim();
        try {
            Certificate certificate = Certificate.loadCertificateFromFile(filename);
            System.out.println(certificate.isSelfSigned());
            System.out.println(certificate.subject == null ? "No subject" : "Subject: "+certificate.subject.getRawString());
            System.out.println(certificate.issuer == null ? "No issuer" : "Issuer: "+certificate.issuer.getRawString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("hahaha3ahha".substring(6));
    }


}