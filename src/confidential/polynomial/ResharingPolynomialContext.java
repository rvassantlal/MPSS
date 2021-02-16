package confidential.polynomial;

public class ResharingPolynomialContext extends PolynomialManagerContext {
    private final int oldF;
    private final int newF;
    private final int[] oldMembers;
    private final int[] newMembers;
    private final PolynomialPoint[] points;

    public ResharingPolynomialContext(int id, int nPolynomials, int oldF,
                                      int newF, int[] oldMembers, int[] newMembers) {
        super(id, nPolynomials);
        this.oldF = oldF;
        this.newF = newF;
        this.oldMembers = oldMembers;
        this.newMembers = newMembers;
        this.points = new PolynomialPoint[nPolynomials];
    }

    public int getOldF() {
        return oldF;
    }

    public int getNewF() {
        return newF;
    }

    public int[] getOldMembers() {
        return oldMembers;
    }

    public int[] getNewMembers() {
        return newMembers;
    }

    public PolynomialPoint[] getPoints() {
        return points;
    }

    public void addPolynomial(int id, PolynomialPoint point) {
        int index = super.id == 0 ? id : id % super.id;
        if (currentIndex == nPolynomials || index >= nPolynomials) {
            return;
        }
        points[index] = point;
        currentIndex++;
    }
}
