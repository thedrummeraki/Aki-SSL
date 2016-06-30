package attributes;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Created by aakintol on 30/06/16.
 */
public class Field {

    /**
     * A field is a data structure containing a key (this is identifiable) and one or more values.
     * */

    private String key;
    private ArrayList<Object> values;

    public Field(String key) throws AttributeException {
        this(key, (Object[]) null);
    }

    public Field(String key, Object... values) throws AttributeException {
        if (key == null || key.trim().isEmpty()) {
            throw new AttributeException("You cannot add a field with an empty key");
        }
        this.values = new ArrayList<>();
        if (values != null) {
            for (Object value : values) {
                if (value != null) {
                    this.values.add(value);
                }
            }
        }
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public ArrayList<Object> getValues() {
        return values;
    }

    @Override
    public String toString() {
        return "["+key+"-> "+this.values.toString()+"]";
    }

    public static Field generateField(String key, Object... values) {
        try {
            return new Field(key, values);
        } catch (AttributeException e) {
            return null;
        }
    }
}
