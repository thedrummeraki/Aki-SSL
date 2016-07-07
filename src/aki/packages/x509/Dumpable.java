package aki.packages.x509;

/**
 * Created by aakintol on 28/06/16.
 */
public interface Dumpable {
    byte[] dumpDER();
    String dumpPEM();
}
