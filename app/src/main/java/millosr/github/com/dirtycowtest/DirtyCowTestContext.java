package millosr.github.com.dirtycowtest;

/**
 * Created by Milos on 11/22/2016.
 */

public interface DirtyCowTestContext {
    public String getFilesPath();
    public void addLogMessage(String message);
    public void testFinished(boolean vulnerable);

    public void setTestProgress(int progress);
}
