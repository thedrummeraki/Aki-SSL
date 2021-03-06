package aki.packages.x509;

import aki.packages.tools.BashReader;
import aki.packages.tools.FileReader;
import aki.packages.tools.FileWriter;
import aki.packages.tools.Logger;

import java.io.File;

/**
 * Created by aakintol on 28/06/16.
 */
public class PrivateKey extends Key {

    private Certificate certificate;
    private Subject subject;

    private PrivateKey() {
        super();
        this.setPrivate();
    }

    public static PrivateKey newInstance() {
        return new PrivateKey();
    }

    public static PrivateKey loadPrivateKey(File file) {
        return loadPrivateKey(BashReader.toSingleString(true, FileReader.getLines(file)));
    }

    public static PrivateKey loadPrivateKey(String buff) {
        PrivateKey privateKey = new PrivateKey();
        privateKey.setPemContents(buff);
        return privateKey;
    }

    public Key create(Subject subject) {
        this.subject = subject;
        return this.create();
    }

    public String dumpPEM(Subject subject) {
        if (pemContents == null) {
            this.create(subject);
        }
        return pemContents;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    @Override
    public Key create() {
        String keyFilename = "tmp/key.key";
        String csrFilename = "tmp/csr.csr";
        String[] args = {"openssl", "req", "-nodes", "-newkey", String.format("%s:%s", this.algorithm, this.bits), "-keyout", keyFilename,
            "-out", csrFilename};
        if (this.subject == null && this.certificate != null && this.certificate.getSubject() != null) {
            this.subject = this.certificate.getSubject();
        }
        if (this.subject != null) {
            args = new String[]{"openssl", "req", "-nodes", "-newkey", String.format("%s:%s", this.algorithm, this.bits), "-keyout", keyFilename,
                        "-out", csrFilename, "-subj", "'" + this.subject.getRawString() + "'"};
        } else {
            Logger.info("PrivateKey", "No subject.");
        }
        BashReader br = BashReader.read(args);
        if (br == null) {
            return null;
        }
        if (br.getExitValue() != 0) {
            Logger.error("PrivateKey", (br.getOutput().isEmpty() ? "No output" : br.getOutput()) + ": " + br.getLines() + " ("+br.getExitValue()+")");
            return null;
        }
        this.pemContents = BashReader.toSingleString(true, FileReader.getLines(keyFilename));
        try {
            this.derContents = toDER(this.pemContents);
        } catch (CertificateException e) {
            Logger.warn("PrivateKey", "Warning! "+e.getLocalizedMessage());
        }
        if (this.certificate != null) {
            this.certificate.setPrivateKey(this);
        }
        Logger.error("PrivateKey", "Private key properly generated.");
        return this;
    }

    @Override
    public void check(Certificate certificate) throws CertificateException {
        // Check if the certificate matches the certificate
        String certificateBlob = certificate.getBlob();
        if (certificateBlob == null || certificateBlob.isEmpty()) {
            throw new CertificateException("The certificate's contents are not valid (empty).");
        }
        if (pemContents == null) {
            if (this.subject == null) {
                this.subject = certificate.getSubject();
            }
            if (this.subject == null) {
                throw new CertificateException("Invalid subject (null).");
            }
        }
        File tempThis = new File("tmp/temp-privKey.key");
        if (!FileWriter.write((pemContents == null ? this.dumpPEM(subject) : pemContents), tempThis.getPath())) {
            throw new CertificateException("Couldn't write the private key to a temporary file.");
        }
        File tempCert = new File("tmp/temp-certif.cert");
        if (!FileWriter.write(certificateBlob, tempCert.getPath())) {
            throw new CertificateException("Couldn't write the certificate to a temporary file.");
        }
        String modKey = Modulus.get(tempThis, false);
        String modCert = Modulus.get(tempCert, true);
        if (modKey == null || modCert == null || !modCert.trim().equals(modKey.trim())) {
            throw new KeyException();
        }
    }

    public String getModulus() {
        File tempThis = new File("tmp/temp-privKey.key");
        if (!FileWriter.write((pemContents == null ? this.dumpPEM(subject) : pemContents), tempThis.getPath())) {
            Logger.error("PrivateKey", "Couldn't write the private key to a temporary file.");
            return null;
        }
        return Modulus.get(dumpPEM(), false);
    }

    public boolean doCheck(Certificate certificate) {
        try {
            check(certificate);
            return true;
        } catch (KeyException e) {
            return false;
        } catch (CertificateException e) {
            e.printStackTrace();
            return false;
        }
    }
}
