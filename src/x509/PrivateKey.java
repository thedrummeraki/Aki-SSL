package x509;

import tools.BashReader;
import tools.FileReader;
import tools.Logger;

/**
 * Created by aakintol on 28/06/16.
 */
public class PrivateKey extends Key {

    private Certificate certificate;
    private Subject subject;

    private PrivateKey() throws CertificateException {
        super(true, false);
    }

    public static PrivateKey newInstance() {
        try {
            return new PrivateKey();
        } catch (CertificateException e) {
            return null;
        }
    }

    @Override
    public Key create() {
        String keyFilename = "tmp/key.key";
        String csrFilename = "tmp/csr.csr";
        String[] args = {"openssl", "req", "-nodes", String.format("%s:%s", this.algorithm, this.bits), "-keyout", keyFilename,
            "-out", csrFilename};
        if (this.subject == null && this.certificate != null && this.certificate.getSubject() != null) {
            this.subject = this.certificate.getSubject();
        }
        if (this.subject != null) {
            args = new String[]{"openssl", "req", "-nodes", String.format("%s:%s", this.algorithm, this.bits), "-keyout", keyFilename,
                        "-out", csrFilename, "-subj", this.subject.getRawString()};
        }
        BashReader br = BashReader.read(args);
        if (br == null) {
            return null;
        }
        this.pemContents = BashReader.toSingleString(FileReader.getLines(keyFilename));
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
}
