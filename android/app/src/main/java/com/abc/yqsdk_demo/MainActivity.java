package com.abc.yqsdk_demo;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;

import androidx.annotation.Nullable;

import yqmobile.ConnectionListener;
import yqmobile.Yqmobile;

public class MainActivity extends Activity {
    private Button mButton;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        mButton = findViewById(R.id.btn);
        mButton.setOnClickListener(view -> {
            try {
                Yqmobile.configureTLS("", "", true);
                Yqmobile.setConnectionListener(new ConnectionListener() {
                    @Override
                    public void onStateChanged(String status, String err) {
                        Log.i("RRR", "status:" + status + ",err:" + err);
                    }
                });

                Yqmobile.start("192.168.200.20:8081");
                new Thread(){
                    @Override
                    public void run() {
                        while(true) {
                            Log.i("RRR", "thread run...");
                            try {
                                Thread.sleep(10000);
                            } catch (InterruptedException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    }
                }.start();
            } catch (Exception e) {
                Log.e("RRR", "exception:" + e);
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
    }
}