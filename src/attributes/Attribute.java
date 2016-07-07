package attributes;

import aki.packages.tools.Logger;
import aki.packages.x509.Signable;

import java.util.ArrayList;

/**
 * Created by aakintol on 28/06/16.
 */
public class Attribute extends Signable {

    private ArrayList<Field> fields;

    private AttributeSet parent;

    public Attribute(AttributeSet attributeSet) {
        if (attributeSet == null) {
            attributeSet = new AttributeSet();
        }
        this.parent = attributeSet;
        this.fields = new ArrayList<>();
        this.updateInParent();
    }

    public ArrayList<Field> getFields() {
        return fields;
    }

    public void addField(Field field) {
        if (field == null) {
            Logger.info(getClass(), "Null field not added.", false);
            return;
        }
        this.fields.add(field);
    }

    public void addField(String key, Object... values) {
        this.addField(Field.generateField(key, values));
    }

    private void updateInParent() {
        if (!parent.contains(this)) {
            parent.add(this);
        }
        parent.update(this);
    }


    public boolean contains(String string) {
        for (Field field : this.fields) {
            if (field.getKey().equals(string)) {
                return true;
            }
        }
        return false;
    }
}
