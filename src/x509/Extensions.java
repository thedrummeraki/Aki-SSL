package x509;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Created by aakintol on 28/06/16.
 */
public class Extensions {

    private ArrayList<Extension> extensions;

    public Extensions() {
        extensions = new ArrayList<>();
    }

    public Extensions(Extension... extensions) {
        this();
        this.extensions.addAll(Arrays.asList(extensions));
    }

    public ArrayList<Extension> getExtensions() {
        return extensions;
    }
}
