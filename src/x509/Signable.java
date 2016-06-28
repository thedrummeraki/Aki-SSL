package x509;

/**
 * Created by aakintol on 28/06/16.
 */
public interface Signable {
    boolean sign() throws Exception;
}
