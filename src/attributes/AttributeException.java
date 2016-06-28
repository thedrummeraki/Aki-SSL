package attributes;

import x509.CertificateException;

/**
 * Created by aakintol on 28/06/16.
 */
public class AttributeException extends CertificateException {

    public AttributeException() {
    }

    public AttributeException(String message) {
        super(message);
    }

    public AttributeException(String message, Throwable cause) {
        super(message, cause);
    }

    public AttributeException(Throwable cause) {
        super(cause);
    }

    public AttributeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
