package aki.packages.pkcs7;

import aki.packages.x509.SignatureException;

/**
 * Created by aakintol on 28/06/16.
 */
public class PKCS7Exception extends SignatureException {

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
