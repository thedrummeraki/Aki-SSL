package pkcs7;

import x509.CertificateException;

/**
 * Created by aakintol on 28/06/16.
 */
public class PKCS7Exception extends CertificateException {

    public PKCS7Exception() {
        super();
    }

    public PKCS7Exception(String message) {
        super(message);
    }

    public PKCS7Exception(String message, Throwable cause) {
        super(message, cause);
    }

    public PKCS7Exception(Throwable cause) {
        super(cause);
    }

    protected PKCS7Exception(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
