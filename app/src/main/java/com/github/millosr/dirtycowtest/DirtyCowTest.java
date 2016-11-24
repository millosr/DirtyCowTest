package com.github.millosr.dirtycowtest;

import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Milos on 11/22/2016.
 */

public class DirtyCowTest {
    private static final String TAG = "DirtyCowTest";

    //private static final String TEST_FILE_DIR = "/sdcard/DirtyCowTest";
    private static final String TEST_FILE = "/sdcard/dirty_cow_test_file";
    private static final String CONTENT = "..............................\n";
    private static final String REPLACEMENT = "1234567890";

    //private String filename;
    private boolean vulnerable = false;
    private boolean aborted = false;

    private boolean running = false;

    private DirtyCowTestContext context;

    public native void openTestFile(String filename);
    public native void madviceLoop();
    public native void procselfmemLoop(String replacement);
    public native void closeTestFile();
    public native void stopLoops();

    public DirtyCowTest(DirtyCowTestContext context) {
        this.context = context;

        //this.filename = context.getFilesPath() + File.separator + TEST_FILE_NAME;
        //this.filename = TEST_FILE_NAME;
    }

    public void abort() {
        if (running) {
            aborted = true;
            running = false;
            stopLoops();
        }
    }

    public void startTest() {
        if (running) {
            return;
        }
        vulnerable = false;
        aborted = false;
        running = true;

        createFile();

        openTestFile(TEST_FILE);

        final Thread t1 = new Thread() {
            public void run() {
                logInfo("madviceLoop started");
                madviceLoop();
                logInfo("madviceLoop finished");
            }
        };
        final Thread t2 = new Thread() {
            public void run() {
                logInfo("procselfmemLoop started");
                procselfmemLoop(REPLACEMENT);
                logInfo("procselfmemLoop finished");
            }
        };
        final Thread t3 = new Thread() {
            public void run() {
                testReplacement();
            }
        };
        final Thread controlThread = new Thread() {
            public void run() {
                try {
                    t1.join();
                    t2.join();
                    running = false;
                    t3.join();
                } catch (InterruptedException e) {
                    logError("Error in controlThread", e);
                }
                closeTestFile();
                if (!aborted) {
                    if (vulnerable) {
                        logError("***** VULNERABLE!!! *****", null);
                    } else {
                        logInfo("NOT vulnerable.");
                    }
                    context.testFinished(vulnerable);
                } else {
                    logInfo("Test aborted");
                }
            }
        };
        t1.start();
        t2.start();
        t3.start();
        controlThread.start();
    }

    private void createFile() {
        try {
            File root = null;
            root = Environment.getExternalStorageDirectory();
            logInfo("path = " +root.getAbsolutePath());
            File fileDir = new File(root.getAbsolutePath()+"/dirtyCowTest/");
            fileDir.mkdirs();

            File newFile = new File(fileDir, "test_file");
            //newFile.mkdirs();
            //newFile.delete();
            //newFile.createNewFile();
            FileWriter fw = new FileWriter(newFile);
            fw.append(CONTENT);
            fw.close();
            //changePermissions(TEST_FILE);
        } catch (Exception e) {
            logError("Error creating file", e);
        }
    }

    private void changePermissions(String fullPath) throws Exception {
        Process process = Runtime.getRuntime().exec("chmod 400 " + fullPath);
        process.waitFor();
    }

    private void testReplacement() {
        logInfo("Test loop started");
        File file = new File(TEST_FILE);
        String s;
        int len = REPLACEMENT.length();
        char [] buff = new char[len];
        char [] replacement = REPLACEMENT.toCharArray();

        FileReader fr = null;
        try {
            while (running) {
                fr = new FileReader(file);
                fr.read(buff, 0, len);
                if (Arrays.equals(buff, replacement)) {
                    vulnerable = true;
                    stopLoops();
                }
            }
        } catch (IOException e) {
            logError("Error reading file", e);
        } finally {
            try {
                fr.close();
            } catch (Exception e) {
                logError("Error closing file", e);
            }
        }
        logInfo("Test loop finished");
    }

    private void logInfo(String message) {
        Log.i(TAG, message);
        context.addLogMessage(message);
    }

    public void logError(String message, Exception e) {
        Log.e(TAG, message, e);
        context.addLogMessage(message);
    }

    public void setTestProgress(int progress) {
        context.setTestProgress(progress);
    }

    public boolean isRunning() {
        return running;
    }

    public boolean isVulnerable() {
        return vulnerable;
    }
}
