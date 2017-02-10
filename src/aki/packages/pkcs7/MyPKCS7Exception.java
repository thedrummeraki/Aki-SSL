package aki.packages.pkcs7;

/**
 * Created by aakintol on 28/06/16.
 */
public class MyPKCS7Exception extends Exception {

    public MyPKCS7Exception() {
        super();
    }

    public MyPKCS7Exception(String message) {
        super(message);
    }

    public MyPKCS7Exception(String message, Throwable cause) {
        super(message, cause);
    }

    public MyPKCS7Exception(Throwable cause) {
        super(cause);
    }

    protected MyPKCS7Exception(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
