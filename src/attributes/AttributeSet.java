package attributes;

import aki.packages.tools.Logger;

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

    public void add(Attribute attribute) {
        this.attributes.add(attribute);
    }

    public boolean remove(Attribute attribute) throws AttributeException {
        if (this.attributes.contains(attribute)) {
            return this.attributes.remove(attribute);
        }
        throw new AttributeException("Attribute " + (attribute == null ? "(null)" : attribute) + " not found");
    }

    public Attribute remove(int index) {
        return this.attributes.remove(index);
    }

    public void update(int index) {
        if (index < 0 || index >= this.size()) {
            return;
        }
        Attribute attr = this.remove(index);
        this.attributes.set(index, attr);
    }

    public void update(Attribute attribute) {
        this.update(indexOf(attribute));
    }

    public Attribute getAttribute(int index) throws AttributeException {
        if (index < 0 || index >= this.attributes.size()) {
            throw new AttributeException("Invalid index: "+index);
        }
        return attributes.get(index);
    }

    public Attribute getAttribute(String key) {
        for (Attribute attribute : this.attributes) {
            for (Field field : attribute.getFields()) {
                if (field.getKey().equals(key)) {
                    return attribute;
                }
            }
        }
        return null;
    }

    public Attribute getLastAttribute() {
        try {
            return this.getAttribute(this.size() - 1);
        } catch (AttributeException e) {
            return null;
        }
    }

    public Attribute pop() {
        if (this.isEmpty()) {
            return null;
        }
        Attribute attribute = getLastAttribute();
        try {
            this.remove(attribute);
        } catch (AttributeException e) {
            Logger.info("AttributeSet", "There is nothing to pop.");
        }
        return attribute;
    }

    public boolean isEmpty() {
        return this.attributes.isEmpty();
    }

    public int size() {
        return this.attributes.size();
    }

    public boolean contains(Attribute attribute) {
        return this.attributes.contains(attribute);
    }

    public boolean contains(String string) {
        for (Attribute attribute : this.attributes) {
            if (attribute.contains(string)) {
                return true;
            }
        }
        return false;
    }

    public int indexOf(Attribute attribute) {
        return this.attributes.indexOf(attribute);
    }

    @Override
    public String toString() {
        return this.attributes.toString();
    }
}
