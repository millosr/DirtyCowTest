package millosr.github.com.dirtycowtest;

import android.app.AlertDialog;
import android.net.Uri;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.google.android.gms.appindexing.Action;
import com.google.android.gms.appindexing.AppIndex;
import com.google.android.gms.appindexing.Thing;
import com.google.android.gms.common.api.GoogleApiClient;

public class MainActivity extends AppCompatActivity implements DirtyCowTestContext {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private DirtyCowTest dirtyCowTest;
    private boolean active;
    private boolean showResultDialogOnStart;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        dirtyCowTest = new DirtyCowTest(this);
        active = false;
        showResultDialogOnStart = false;

        Button button = (Button) findViewById(R.id.testButton);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (dirtyCowTest.isRunning()) {
                    dirtyCowTest.abort();
                } else {
                    dirtyCowTest.startTest();
                }
                setUiElements();
            }
        });
        TextView outputText = (TextView) findViewById(R.id.outputText);
        outputText.setMovementMethod(new ScrollingMovementMethod());
    }

    private void setUiElements() {
        boolean running = dirtyCowTest.isRunning();
        ProgressBar progressBar = (ProgressBar) findViewById(R.id.testProgress);
        progressBar.setVisibility(running ? View.VISIBLE : View.GONE);
        Button button = (Button) findViewById(R.id.testButton);
        button.setText(running ? R.string.button_abort : R.string.button_start);
    }

    @Override
    public void onStart() {
        super.onStart();
        active = true;
        if (showResultDialogOnStart) {
            showResultDialogOnStart = false;
            showResultDialog(dirtyCowTest.isVulnerable());
        } else {
            findViewById(R.id.testButton).requestFocus();
        }
    }

    @Override
    public void onStop() {
        super.onStop();
        active = false;
    }

    @Override
    protected void onDestroy() {
        if (dirtyCowTest.isRunning()) {
            dirtyCowTest.abort();
        }
        super.onDestroy();
    }

    @Override
    public String getFilesPath() {
        return getApplicationContext().getFilesDir().getAbsolutePath();
    }

    @Override
    public void addLogMessage(final String message) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                appendOutputText("\n" + message);
            }
        });
    }

    private void appendOutputText(String text) {
        TextView outputText = (TextView) findViewById(R.id.outputText);
        String newText = outputText.getText() + text;
        outputText.setText(newText);

        int scrollAmount = outputText.getLayout().getLineTop(outputText.getLineCount()) - outputText.getHeight();
        outputText.scrollTo(0, (scrollAmount > 0) ? scrollAmount: 0);
    }

    @Override
    public void testFinished(final boolean vulnerable) {
        if (active) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    showResultDialog(vulnerable);
                }
            });
        } else {
            showResultDialogOnStart = true;
        }
    }

    private void showResultDialog(boolean vulnerable) {
        Button button = (Button) findViewById(R.id.testButton);
        button.setText(R.string.button_test_again);
        ProgressBar progressBar = (ProgressBar) findViewById(R.id.testProgress);
        progressBar.setVisibility(View.GONE);
        if (vulnerable) {
            new AlertDialog.Builder(MainActivity.this)
                    .setTitle(R.string.vulnerable_title)
                    .setMessage(R.string.vulnerable_text)
                    .setIcon(android.R.drawable.ic_dialog_alert)
                    .setPositiveButton(android.R.string.ok, null)
                    .show();
        } else {
            new AlertDialog.Builder(MainActivity.this)
                    .setTitle(R.string.not_vulnerable_title)
                    .setMessage(R.string.not_vulnerable_text)
                    .setIcon(android.R.drawable.ic_dialog_info)
                    .setPositiveButton(android.R.string.ok, null)
                    .show();
        }
    }

    public void setTestProgress(final int progress) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                ProgressBar progressBar = (ProgressBar) findViewById(R.id.testProgress);
                progressBar.setProgress(progress);
            }
        });
    }
}
