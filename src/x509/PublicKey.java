package x509;

import tools.BashReader;
import tools.FileReader;

/**
 * Created by aakintol on 28/06/16.
 */
public class PublicKey extends Key {

    PublicKey() throws CertificateException {
    }

    @Override
    public Key create() {
        return null;
    }

    public static PublicKey newInstance() {
        try {
            return new PublicKey();
        } catch (CertificateException e) {
            return null;
        }
    }

    void setPEMContents(Certificate certificate) {
        this.pemContents = BashReader.toSingleString(true, FileReader.getLines(certificate.getPublicKeyFilename()));
    }

    public String getPEMContents() {
        return this.pemContents;
    }

    @Override
    public void check(Certificate certificate) throws CertificateException {

    }
}
