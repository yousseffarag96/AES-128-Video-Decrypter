package com.example.hp.decryption;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class MainActivity extends AppCompatActivity {
    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };
    private Button decry;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        verifyStoragePermissions(this);
        decry=(Button)findViewById(R.id.decry);
        final Encrypter encrypter=new Encrypter();
        decry.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try
                {
                    byte[] encodedKey = Base64.decode("Mk9nYNWASQeEduqNsVUvwA==", Base64.DEFAULT);
                    SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
                    File infile=new File("/storage/emulated/0/hopa/z.mp4");
                    String satate =Environment.getExternalStorageState();
                    File root = Environment.getExternalStorageDirectory();
                    File dir = new File(root.getAbsolutePath() + "/xc");
                    File out = new File(dir, "Movie7.mp4");
                    if(Environment.MEDIA_MOUNTED.equals(satate)) {
                        if (!dir.exists()) {
                            dir.mkdir();
                        }
                        encodedKey=key.getEncoded();
                        try{
                            byte[]fildata=   EncryptionModule.readFile(infile);
                            byte[] decry_file=   EncryptionModule.decodeFile(encodedKey,fildata);
                            FileOutputStream fos = new FileOutputStream(out.getPath());
                            try {
                                fos.write(decry_file);
                            }finally {
                                fos.close();
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                    }
                    Toast.makeText(getApplicationContext(),"Decryption is finished",Toast.LENGTH_LONG).show();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

    }
    public static void verifyStoragePermissions(Activity activity) {
        // Check if we have write permission
        int permission = ActivityCompat.checkSelfPermission(activity, Manifest.permission.READ_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            // We don't have permission so prompt the user
            ActivityCompat.requestPermissions(
                    activity,
                    PERMISSIONS_STORAGE,
                    REQUEST_EXTERNAL_STORAGE
            );
        }
    }

}
