package attributes;

import x509.Signable;

/**
 * Created by aakintol on 28/06/16.
 */
public class Attribute implements Signable {

    @Override
    public boolean sign() throws AttributeException {
        return false;
    }
}
