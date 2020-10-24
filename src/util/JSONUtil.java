package util;

import org.json.JSONArray;
import org.json.JSONObject;

public class JSONUtil {

    /**
     * Determine whether the jsonobject is in the array
     */
    public static boolean contains(JSONArray array, JSONObject obj) {
        for (Object o: array) {
            if (o instanceof JSONObject) {
                if (obj.toString().equals(((JSONObject) o).toString()))
                    return true;
            }
        }
        return false;
    }
}
