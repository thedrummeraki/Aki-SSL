package aki.packages.scep;

import java.io.Serializable;

/**
 * Created by aakintol on 19/07/16.
 */
public class ResponseStatus implements Serializable {

    private static final long serialVersionUID = -1424581065308042345L;

    /**
     * Request granted
     */
    public static final ResponseStatus SUCCESS = new ResponseStatus(0);

    /**
     * Request granted with mods. Indicates the requester got something like what you asked for.
     * The requester is responsible for ascertaining the differences.
     */
    public static final ResponseStatus GRANTED_WITH_MODS = new ResponseStatus(1);

    /**
     * Request rejected
     */
    public static final ResponseStatus FAILURE = new ResponseStatus(2);

    /**
     * Request pending for approval
     */
    public static final ResponseStatus PENDING = new ResponseStatus(3);

    /**
     * The value actually encoded into the response message as a pkiStatus attribute
     */
    private final int value;

    private ResponseStatus(final int value) {
        this.value = value;
    }

    /**
     * Gets the value embedded in the response message as a pkiStatus attribute
     * @return  the value to use
     */
    public String getStringValue() {
        return Integer.toString(value);
    }

    public int getValue() {
        return value;
    }

    public boolean equals(final Object o) {
        boolean ret = false;
        if (this == o) {
            ret = true;
        } else {
            if (o instanceof ResponseStatus) {
                final ResponseStatus status = (ResponseStatus) o;
                if (value == status.getValue()) {
                    ret = true;
                }
            }
        }
        return ret;
    }

    public int hashCode() {
        return value;
    }

}
