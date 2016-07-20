package aki.packages.scep;

/**
 * Created by aakintol on 19/07/16.
 */

import java.io.ByteArrayOutputStream;

/**
 * This class implements a BASE64 Character encoder/decoder as specified in RFC1521.
 * It extends the bouncycastle implementation and adds the functionality to split lines
 * with a '\n' after every 64 bytes.
 *
 * @version $Id: Base64.java 19902 2014-09-30 14:32:24Z anatom $
 */
public final class Base64 {

    private Base64 () {} // Not for instantiation

    /**
     * encode the input data producing a base 64 encoded byte array with the output lines be split by '\n' (64 byte rows).
     *
     * @param data data to be encoded
     * @return a byte array containing the base 64 encoded data.
     */
    public static byte[] encode(final byte[] data) {
        return encode(data, true);
    }

    /**
     * encode the input data producing a base 64 encoded byte array.
     *
     * @param data the data to be encoded
     * @param splitlines whether the output lines will be split by '\n' (64 byte rows) or not.
     * @return a byte array containing the base 64 encoded data.
     */
    public static byte[] encode(final byte[] data, final boolean splitlines) {
        byte[] bytes = org.bouncycastle.util.encoders.Base64.encode(data);
        if (splitlines) {
            // make sure we get limited lines...
            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            for (int i = 0; i < bytes.length; i += 64) {
                if ((i + 64) < bytes.length) {
                    os.write(bytes, i, 64);
                    os.write('\n');
                } else {
                    os.write(bytes, i, bytes.length - i);
                }
            }
            bytes = os.toByteArray();
        }
        return bytes;

    }

    public static byte[] decode(final byte[] bytes) {
        return org.bouncycastle.util.encoders.Base64.decode(bytes);
    }

}
