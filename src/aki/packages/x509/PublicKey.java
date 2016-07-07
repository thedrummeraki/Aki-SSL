package aki.packages.x509;

import aki.packages.tools.BashReader;
import aki.packages.tools.FileReader;

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
        String publicKeyFilename = certificate.getPublicKeyFilename();
        if (publicKeyFilename == null) {
            return;
        }
        this.pemContents = BashReader.toSingleString(true, FileReader.getLines(publicKeyFilename));
    }

    public String getPEMContents() {
        return this.pemContents;
    }

    @Override
    public void check(Certificate certificate) throws CertificateException {

    }
}
