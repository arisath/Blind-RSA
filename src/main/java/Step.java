
public class Step {
    private final int step;
    private final String actor;
    private final String action;
    private final String detail;
    private final String payload;  // Can be JSON string or plain text

    public Step(int step, String actor, String action, String detail, String payload) {
        this.step = step;
        this.actor = actor;
        this.action = action;
        this.detail = detail;
        this.payload = payload;
    }

    // Getters
    public int getStep() { return step; }
    public String getActor() { return actor; }
    public String getAction() { return action; }
    public String getDetail() { return detail; }
    public String getPayload() { return payload; }
}
