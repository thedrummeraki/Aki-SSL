package x509;

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

    @Override
    public void check(Certificate certificate) throws CertificateException {

    }
}
