
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class VisualizerLogger {

    private final List<Step> steps = Collections.synchronizedList(new ArrayList<>());

    /**
     * Record a step in the blind RSA exchange.
     *
     * @param step    Sequential step number
     * @param actor   Actor performing the action ("Alice" or "Bob")
     * @param action  Short description (e.g. "Signs blinded message")
     * @param detail  Human-readable explanation of what’s happening
     * @param payload Structured JSON/text representing data (keys, messages, signatures)
     */
    public void add(int step, String actor, String action, String detail, String payload) {
        steps.add(new Step(step, actor, action, detail, payload));
    }

    /**
     * Saves the recorded steps to a JSON file for visualization.
     *
     * @param filename File path (e.g. "output.json")
     * @throws IOException if writing fails
     */
    public void save(String filename) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(filename)) {
            gson.toJson(steps, writer);
        }
    }

    /**
     * Convenience method for debugging – prints all steps to console.
     */
    public void printToConsole() {
        for (Step s : steps) {
            System.out.printf("[%d] %s → %s | %s%n", s.getStep(), s.getActor(), s.getAction(), s.getDetail());
        }
    }
}
