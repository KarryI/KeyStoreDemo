package com.demo.keystore;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ComponentCallbacks;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.support.v7.widget.DividerItemDecoration;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Adapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

public class MainActivity extends Activity {
    private String TAG = MainActivity.class.getSimpleName();
    private RecyclerView recyclerView;
    private Adapter adapter;
    private List<String> aliasList  = new ArrayList<>();
    private EditText editText;
    private TextView tvKey;
    private TextView tvCipher;

    private String plainText; //明文
    private String encryptData; //加密后字符串

    private String currentSelectedKeyAlias;
    private Button button;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();

        KeyStoreUtil.get().generateKey(MainActivity.this,"qq");
        updateKeys();

        //验证数据签名
        String data = "1234";
        byte[] sign = KeyStoreUtil.get().sign(data.getBytes(), "qq");
//        System.out.println("verify: "+KeyStoreUtil.get().verify(data.getBytes(), sign, "qq"));
        Log.d(TAG,"byte="+new String(sign));

        String sign1 = KeyStoreUtil.get().sign(data, "qq");
        Log.d(TAG,"string="+sign1);
        System.out.println("verify: "+KeyStoreUtil.get().verify(data, sign1, "qq"));

        button = findViewById(R.id.imp);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

            }
        });
    }

    private void updateKeys() {
        aliasList.clear();
        Enumeration<String> aliases = KeyStoreUtil.get().getAliases();
        if (aliases!= null){
            while (aliases.hasMoreElements()){
                aliasList.add(aliases.nextElement());
            }
        }
        adapter.notifyDataSetChanged();
    }

    private void initViews() {
        recyclerView = findViewById(R.id.recyclerview);
        recyclerView.setLayoutManager(new LinearLayoutManager(getApplicationContext()));
        recyclerView.addItemDecoration(new DividerItemDecoration(getBaseContext(), DividerItemDecoration.VERTICAL));
        adapter = new Adapter();
        adapter.setItemClickListener(itemClickListener);
        recyclerView.setAdapter(adapter);

        editText = findViewById(R.id.edit_text);
        tvKey = findViewById(R.id.tv_current);
        tvCipher = findViewById(R.id.tv_cipher);

        tvKey.setText(getString(R.string.current_key, ""));

        plainText = getString(R.string.plaintext);
    }

    @Override
    protected void onPause() {
        super.onPause();

        if (isFinishing()){
            aliasList.clear();
        }
    }

    public void onAddKey(View view){
        String alias = editText.getText().toString();
        if (!TextUtils.isEmpty(alias)){
            KeyStoreUtil.get().generateKey(getBaseContext(), alias);
            updateKeys();
        }
    }

    public void onDeleteKey(View view){
        deleteKey(editText.getText().toString());
    }

    private void deleteKey(String alias){
        if (!TextUtils.isEmpty(alias)){
            KeyStoreUtil.get().deleteKey(alias);
            updateKeys();
        }
    }

    private OnItemClickListener itemClickListener = new OnItemClickListener() {
        @Override
        public void onItemClick(View view, int position) {
            currentSelectedKeyAlias = aliasList.get(position);
            tvKey.setText(getString(R.string.current_key, currentSelectedKeyAlias));
        }

        @Override
        public boolean onItemLongClick(View view, int position) {
            deleteKey(aliasList.get(position));
            return true;
        }
    };

    public void doEncrypt(View view) {
        if (currentSelectedKeyAlias == null){
            Toast.makeText(getApplicationContext(), "请先选取alias", Toast.LENGTH_SHORT).show();
            return;
        }
        byte[] data = KeyStoreUtil.get().encrypt(plainText.getBytes(), currentSelectedKeyAlias);
        if (data != null){
            encryptData = Base64.encodeToString(data, Base64.DEFAULT);
            tvCipher.setText(getString(R.string.encrypt_content, encryptData));
        }
    }

    public void doDecrypt(View view) {
        if (currentSelectedKeyAlias == null){
            Toast.makeText(getApplicationContext(), "请先选取alias", Toast.LENGTH_SHORT).show();
            return;
        }
        byte[] data = KeyStoreUtil.get().decrypt(Base64.decode(encryptData, Base64.DEFAULT), currentSelectedKeyAlias);
        if (data != null){
            tvCipher.setText(getString(R.string.decrypt_content, new String(data)));
        }
    }

    private class  ViewHolder extends RecyclerView.ViewHolder{
        TextView textView;
        public ViewHolder(View itemView) {
            super(itemView);

            textView = itemView.findViewById(R.id.tv_name);
        }
    }

    private class Adapter extends RecyclerView.Adapter<ViewHolder> {
        private OnItemClickListener itemClickListener;
        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = getLayoutInflater().inflate(R.layout.layout_item, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, @SuppressLint("RecyclerView") final int position) {
            holder.textView.setText(aliasList.get(position));

            holder.itemView.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (itemClickListener != null){
                        itemClickListener.onItemClick(v, position);
                    }
                }
            });

            holder.itemView.setOnLongClickListener(new View.OnLongClickListener() {
                @Override
                public boolean onLongClick(View v) {
                    if (itemClickListener != null){
                        return itemClickListener.onItemLongClick(v, position);
                    }
                    return false;
                }
            });
        }

        @Override
        public int getItemCount() {
            return aliasList.size();
        }

        public void setItemClickListener(OnItemClickListener itemClickListener){
            this.itemClickListener = itemClickListener;
        }

    }

    public interface OnItemClickListener{
        void onItemClick(View view, int position);

        boolean onItemLongClick(View view, int position);
    }

    public void importKey(final String path){
        new Thread(){
            @Override
            public void run() {
                super.run();
                String KEYSTORE_PASSWORD = "123456";
                File keyStoreFile = new File(path);
                KeyStore fileKeyStore = null;
                if (!keyStoreFile.exists()) {
                    Log.e(TAG,"file no exist");
                    return ;
                }

                try (InputStream in = new FileInputStream(keyStoreFile)) {
                    fileKeyStore = KeyStore.getInstance("PKCS12");
                    fileKeyStore.load(in, KEYSTORE_PASSWORD.toCharArray());

                    Enumeration<String> aliases = fileKeyStore.aliases();
                    Log.d(TAG,"aliases.hasMoreElements()="+aliases.hasMoreElements());
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        if (!KeyStoreUtil.get().containsAlias(alias)) {
                            Log.i(TAG, "Import entry [" + alias + "] to KeyStore.");
                            String pubkey = getPubKey(fileKeyStore, alias);
                            Log.d(TAG, "pubkey [" + alias + "] " + pubkey);
                            String prvkey = getPrvKey(fileKeyStore, alias);
                            Log.d(TAG, "prvkey [" + alias + "] " + prvkey);

                            KeyStore.Entry entry = fileKeyStore.getEntry(alias, null);
                            KeyStoreUtil.get().setEntry(alias, entry, null);
                        }else{
                            Log.d(TAG,"contains : "+alias);
                        }
                    }
                } catch (UnrecoverableEntryException e) {
                    e.printStackTrace();
                } catch (FileNotFoundException e){
                    e.printStackTrace();
                } catch (IOException e){
                    e.printStackTrace();
                } catch (KeyStoreException e){
                    e.printStackTrace();
                } catch (CertificateException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        }.start();

    }

    private String getPubKey(KeyStore keyStore, String alias) {
        KeyStore.PrivateKeyEntry entry = null;
        byte[] en_key = null;
        try {
            entry = (KeyStore.PrivateKeyEntry)
                    keyStore.getEntry(alias, null);
            Key key = entry.getCertificate().getPublicKey();

            en_key = key.getEncoded();
            if (null == en_key) {
                return null;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        if(en_key != null){
            return Base64.encodeToString(en_key, 0);
        }else{
            return null;
        }
    }

    private String getPrvKey(KeyStore keyStore, String alias) {
        KeyStore.PrivateKeyEntry entry = null;
        byte[] en_key = null;
        try {
            entry = (KeyStore.PrivateKeyEntry)
                    keyStore.getEntry(alias, null);
            Key key = entry.getPrivateKey();

            en_key = key.getEncoded();
            if (null == en_key) {
                return null;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        if(en_key != null){
            return Base64.encodeToString(en_key, 0);
        }else{
            return null;
        }
    }

    @Override
    public void onLowMemory() {
        super.onLowMemory();
        Log.e(TAG,"onLowMemory()");
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        Log.e(TAG,"onTrimMemory()");
    }
}
