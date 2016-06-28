package attributes;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Created by aakintol on 28/06/16.
 */
public class AttributeSet {

    private ArrayList<Attribute> attributes;

    public AttributeSet() {
        attributes = new ArrayList<>();
    }

    public AttributeSet(Attribute... attributes) {
        this();
        this.attributes.addAll(Arrays.asList(attributes));
    }

    public ArrayList<Attribute> getAttributes() {
        return attributes;
    }
}
