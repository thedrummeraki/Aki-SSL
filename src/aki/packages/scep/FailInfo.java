package aki.packages.scep;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by aakintol on 19/07/16.
 */
public class FailInfo implements Serializable {

    /**
     * For more info: look at org.cesecore.certificates.certificate.request.FailInfo's javadoc.
     * */

    private static final long serialVersionUID = 5198024740242161138L;

    private static final int[] ACCEPTED_VALUES = {
            0,
            1,
            2,
            3,
            4,
            6,
            7,
            9,
            23
    };

    /**
     * Unrecognized or unsupported algorithm ident
     */
    public static final FailInfo BAD_ALGORITHM = new FailInfo(0);

    /**
     * Integrity check failed
     */
    public static final FailInfo BAD_MESSAGE_CHECK = new FailInfo(1);

    /**
     * Transaction not permitted or supported
     */
    public static final FailInfo BAD_REQUEST = new FailInfo(2);

    /**
     * Message time field was not sufficiently close to the system time
     */
    public static final FailInfo BAD_TIME = new FailInfo(3);

    /**
     * No certificate could be identified matching the provided criteria
     */
    public static final FailInfo BAD_CERTIFICATE_ID = new FailInfo(4);
    /**
     * Request for wrong certificate authority
     */
    public static final FailInfo WRONG_AUTHORITY = new FailInfo(6);
    /**
     * Data incorrect, for example request for a non-existing user
     */
    public static final FailInfo INCORRECT_DATA = new FailInfo(7);
    /**
     * Verification of Proof of possession failed
     */
    public static final FailInfo BAD_POP = new FailInfo(9);
    /**
     * Not authorized
     */
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
        return (this == o || o instanceof FailInfo) && value == ((FailInfo) o).value;
    }

    public int hashCode() {
        return value;
    }
    public String toString() {
        return Integer.toString(value);
    }

    public static FailInfo init(int value) {
        boolean found = false;
        for (int v : ACCEPTED_VALUES) {
            if (value == v) {
                found = true;
                break;
            }
        }
        if (!found) {
            List list = Arrays.asList(ACCEPTED_VALUES);
            throw new IllegalArgumentException("Invalid fail info integer: "+value+". Expected one of: "+ list);
        }
        return new FailInfo(value);
    }

}
