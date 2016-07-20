package aki.packages.scep;

import java.io.Serializable;

/**
 * Created by aakintol on 19/07/16.
 */
public class FailInfo implements Serializable {

    /**
     * For more info: look at org.cesecore.certificates.certificate.request.FailInfo's javadoc.
     * */

    private static final long serialVersionUID = 5198024740242161138L;

    public static final FailInfo BAD_ALGORITHM = new FailInfo(0);
    public static final FailInfo BAD_MESSAGE_CHECK = new FailInfo(1);
    public static final FailInfo BAD_REQUEST = new FailInfo(2);
    public static final FailInfo BAD_TIME = new FailInfo(3);
    public static final FailInfo BAD_CERTIFICATE_ID = new FailInfo(4);
    public static final FailInfo WRONG_AUTHORITY = new FailInfo(6);
    public static final FailInfo INCORRECT_DATA = new FailInfo(7);
    public static final FailInfo BAD_POP = new FailInfo(9);
    public static final FailInfo NOT_AUTHORIZED = new FailInfo(23);

    private final int value;

    private FailInfo(int value) {
        this.value = value;
    }

    public String getValue() {
        return Integer.toString(value);
    }

    public int intValue() {
        return value;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FailInfo)) {
            return false;
        }
        final FailInfo scepResponseStatus = (FailInfo) o;
        if (value != scepResponseStatus.value) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return value;
    }
    public String toString() {
        return Integer.toString(value);
    }

}
