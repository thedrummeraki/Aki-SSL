package x509;

/**
 * Created by aakintol on 04/07/16.
 */
public class KeyException extends CertificateException {

    public KeyException() {
    }

    public KeyException(String message) {
        super(message);
    }

    public KeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public KeyException(Throwable cause) {
        super(cause);
    }

    public KeyException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
