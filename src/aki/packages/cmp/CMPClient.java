package aki.packages.cmp;

import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

/**
 * Created by aakintol on 20/01/17.
 */
public abstract class CMPClient {

    private ProtectedPKIMessage message;

    abstract void request() throws Exception;
    abstract ProtectedPKIMessage getMessage();

    protected void setMessage(ProtectedPKIMessage message) {
        this.message = message;
    }

    protected ProtectedPKIMessage message() {
        return this.message;
    }
}
