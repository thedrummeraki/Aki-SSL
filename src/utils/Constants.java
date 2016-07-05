package utils;

/**
 * Created by aakintol on 05/07/16.
 */
public final class Constants {

    private Constants() {}

    /**
     * When a needed object is null in a function.
     * */
    public static final int NULL_OBJECT_ERROR = 200;

    /**
     * When a created object is null during the function's execution.
     * */
    public static final int NULL_OBJECT_RESULT_ERROR = 199;

    /**
     * When there is an IOException.
     * */
    public static final int IO_WRITE_ERROR = 198;

    /**
     * A certificate and a private don't match.
     * */
    public static final int CHECK_CERTIFICATE_PRIVATE_KEY_ERROR = 1;

    /**
     * A signable object is not valid or not signed.
     * */
    public static final int CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR = 2;

    /**
     * A certificate is invalid.
     * */
    public static final int INVALID_CERTIFICATE_ERROR = 3;

}
