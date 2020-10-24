package base;

import java.util.ArrayList;
import java.util.List;

public class BaseConstraints {

    public List<Long> lowerBounds = new ArrayList<>();
    public List<Long> upperBounds = new ArrayList<>();

    public BaseConstraints(List<Long> lower, List<Long> upper) {
        this.lowerBounds = lower;
        this.upperBounds = upper;
    }

    public int getLength() { return lowerBounds.size(); }

    public List<Long> getConstraint(int index) {
        List<Long> constraint = new ArrayList<>();
        constraint.add(lowerBounds.get(index));
        constraint.add(upperBounds.get(index));

        return constraint;
    }
}
