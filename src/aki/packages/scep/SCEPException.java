package aki.packages.scep;

import aki.packages.pkcs7.PKCS7Exception;

/**
 * Created by aakintol on 30/06/16.
 */
public class SCEPException extends PKCS7Exception {

    public SCEPException() {
    }

    public SCEPException(String message) {
        super(message);
    }

    public SCEPException(String message, Throwable cause) {
        super(message, cause);
    }

    public SCEPException(Throwable cause) {
        super(cause);
    }

    public SCEPException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
