package com.breadwallet.tools.manager;

import android.content.Context;
import android.os.NetworkOnMainThreadException;
import android.support.annotation.WorkerThread;
import android.text.format.DateUtils;
import android.util.Log;

import com.breadwallet.model.FeeOption;
import com.breadwallet.model.PriceChange;
import com.breadwallet.presenter.entities.CurrencyEntity;
import com.breadwallet.repository.FeeRepository;
import com.breadwallet.repository.RatesRepository;
import com.breadwallet.tools.animation.UiUtils;
import com.breadwallet.tools.threads.executor.BRExecutor;
import com.breadwallet.tools.util.BRConstants;
import com.breadwallet.tools.util.Utils;
import com.breadwallet.wallet.WalletsMaster;
import com.breadwallet.wallet.abstracts.BaseWalletManager;
import com.breadwallet.wallet.wallets.bitcoin.BaseBitcoinWalletManager;
import com.breadwallet.wallet.wallets.bitcoin.WalletBitcoinManager;
import com.breadwallet.wallet.wallets.ethereum.WalletEthManager;
import com.platform.APIClient;
import com.platform.network.service.CurrencyHistoricalDataClient;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.math.BigDecimal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import okhttp3.Request;

/**
 * BreadWallet
 * <p>
 * Created by Mihail Gutan <mihail@breadwallet.com> on 7/22/15.
 * Copyright (c) 2016 breadwallet LLC
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

public final class BRApiManager {
    private static final String TAG = BRApiManager.class.getName();
    private static final String BIT_PAY_URL = "https://bitpay.com/rates";
    private static final String DATE_FORMAT = "EEE, dd MMM yyyy HH:mm:ss z";
    private static final String CURRENCY_QUERY_STRING = "/rates?currency=";
    private static final String CURRENCIES_PATH = "/currencies";
    private static final String NAME = "name";
    private static final String CODE = "code";
    private static final String RATE = "rate";
    private static final String PRICE_BTC = "price_btc";
    private static final String SYMBOL = "symbol";
    private static final String TOKEN_RATES_URL_PREFIX = "https://min-api.cryptocompare.com/data/pricemulti?fsyms=";
    private static final String TOKEN_RATES_URL_SUFFIX = "&tsyms=BTC";
    private static final int FSYMS_CHAR_LIMIT = 300;
    private static final String CONTRACT_INITIAL_VALUE = "contract_initial_value";
    private static final String FEE_URL_FORMAT = "%s/fee-per-kb?currency=%s";
    private static final String FEE_FIELD_REGULAR = "fee_per_kb";
    private static final String FEE_FIELD_ECONOMY = "fee_per_kb_economy";
    private static final String FEE_FIELD_PRIORITY = "fee_per_kb_priority";

    private static BRApiManager mInstance;
    private Timer mTimer;
    private TimerTask mTimerTask;

    private BRApiManager() {
    }

    public static BRApiManager getInstance() {
        if (mInstance == null) {
            mInstance = new BRApiManager();
        }
        return mInstance;
    }

    /**
     * Retrieves fee rates for the given currency and stores them in the fee repository.
     * @param context the context
     * @param currencyCode the currency for which fee rates are being retrieved
     */
    public static void updateFeeForCurrency(Context context, String currencyCode) {
        String feeUpdateJSONStr = BRApiManager.urlGET(context, String.format(FEE_URL_FORMAT, APIClient.getBaseURL(), currencyCode));
        long timestamp = System.currentTimeMillis();

        if (Utils.isNullOrEmpty(feeUpdateJSONStr)) {
            Log.e(TAG, "updateFeePerKb: failed to update fee, response string: " + feeUpdateJSONStr);
            return;
        }

        try {
            JSONObject feeUpdateJSONObj = new JSONObject(feeUpdateJSONStr);

            BigDecimal fee = new BigDecimal(feeUpdateJSONObj.getString(FEE_FIELD_REGULAR));
            BigDecimal economyFee = new BigDecimal(feeUpdateJSONObj.getString(FEE_FIELD_ECONOMY));
            BigDecimal priorityFee = new BigDecimal(feeUpdateJSONObj.getString(FEE_FIELD_PRIORITY));

            Log.d(TAG, "updateFee: " + currencyCode + ":" + fee + "|" + economyFee + " | " + priorityFee);

            if (fee.compareTo(BigDecimal.ZERO) > 0) {
                FeeRepository.getInstance(context).putFeeForCurrency(currencyCode, fee, FeeOption.REGULAR, timestamp);
            } else {
                BRReportsManager.reportBug(new NullPointerException("Fee is weird:" + fee));
                Log.d(TAG, "Error: Fee is unexpected value");
            }

            if (economyFee.compareTo(BigDecimal.ZERO) > 0) {
                FeeRepository.getInstance(context).putFeeForCurrency(currencyCode, economyFee, FeeOption.ECONOMY, timestamp);
            } else {
                BRReportsManager.reportBug(new NullPointerException("Economy fee is weird:" + economyFee));
                Log.d(TAG, "Error: Economy fee is unexpected value");
            }

            if (priorityFee.compareTo(BigDecimal.ZERO) > 0) {
                FeeRepository.getInstance(context).putFeeForCurrency(currencyCode, priorityFee, FeeOption.PRIORITY, timestamp);
            } else {
                BRReportsManager.reportBug(new NullPointerException("Priority fee is weird:" + economyFee));
                Log.d(TAG, "Error: Priority fee is unexpected value");
            }

        } catch (JSONException e) {
            Log.e(TAG, "updateFeePerKb: FAILED: " + feeUpdateJSONStr, e);
            BRReportsManager.reportBug(e);
            BRReportsManager.reportBug(new IllegalArgumentException("JSON ERR: " + feeUpdateJSONStr));
        }
    }

    @WorkerThread
    private void updateFiatRates(Context context) {
        if (UiUtils.isMainThread()) {
            throw new NetworkOnMainThreadException();
        }
        Set<CurrencyEntity> set = new LinkedHashSet<>();
        try {
            JSONArray arr = fetchFiatRates(context);
            if (arr != null) {
                int length = arr.length();
                for (int i = 0; i < length; i++) {
                    CurrencyEntity currencyEntity = new CurrencyEntity();
                    try {
                        Double rate=1d;
                        JSONObject tmpObj = (JSONObject) arr.get(i);
                        //String code=tmpObj.getString(CODE).toLowerCase();
//                        if(code.equalsIgnoreCase("usd")
//                                ||code.equalsIgnoreCase("cny")
//                                )
//
//                        {
//                            rate=WalletBitcoinManager.RATE;
//                        }
//                        else if( code.equalsIgnoreCase("btc"))
//                        {
//                            rate=WalletBitcoinManager.RATE;
//                        }

                        currencyEntity.name = tmpObj.getString(NAME);
                        currencyEntity.code = tmpObj.getString(CODE);
                        currencyEntity.rate = Float.valueOf(tmpObj.getString(RATE));
                        //currencyEntity.rate = (float)(Double.valueOf(tmpObj.getString(RATE))/rate);
                        currencyEntity.iso = WalletBitcoinManager.BITCOIN_CURRENCY_CODE;
                    } catch (JSONException e) {
                        Log.e(TAG, "updateFiatRates: ", e);
                    }
                    set.add(currencyEntity);
                }
            } else {
                Log.e(TAG, "getCurrencies: failed to get currencies, response string: " + arr);
            }
        } catch (Exception e) {
            Log.e(TAG, "updateFiatRates: ", e);
        }
        if (set.size() > 0) {
            RatesRepository.getInstance(context).putCurrencyRates(set);
        }

    }

    private void initializeTimerTask(final Context context) {
        mTimerTask = new TimerTask() {
            public void run() {
                updateData(context);
            }
        };
    }

    /** Synchronously updates RateRepository data. */
    @WorkerThread
    public void updateRatesSync(final Context context) {
        Log.d(TAG, "Fetching rates");
        //Update Crypto Rates
        List<String> codeList = WalletsMaster.getInstance().getAllCurrencyCodesPossible(context);
        updateCryptoRates(context, codeList);

        //Update BTC/Fiat rates
        updateFiatRates(context);
    }

    @WorkerThread
    private void updateData(final Context context) {
        Log.d(TAG, "Fetching rates");
        final List<String> codeList = WalletsMaster.getInstance().getAllCurrencyCodesPossible(context);
        BRExecutor.getInstance().forLightWeightBackgroundTasks().execute(new Runnable() {
            @Override
            public void run() {
                //Update Crypto Rates
                updateCryptoRates(context, codeList);
                //Update new tokens rate (e.g. CCC)
                fetchNewTokensData(context);
            }
        });
        BRExecutor.getInstance().forLightWeightBackgroundTasks().execute(new Runnable() {
            @Override
            public void run() {
                fetchPriceChanges(context, codeList);
            }
        });
        BRExecutor.getInstance().forLightWeightBackgroundTasks().execute(new Runnable() {
            @Override
            public void run() {
                //Update BTC/Fiat rates
                updateFiatRates(context);
            }
        });
        List<BaseWalletManager> list = new ArrayList<>(WalletsMaster.getInstance().getAllWallets(context));
        for (final BaseWalletManager walletManager : list) {
            BRExecutor.getInstance().forLightWeightBackgroundTasks().execute(new Runnable() {
                @Override
                public void run() {
                    if(walletManager==null)
                    {

                    }
                    walletManager.updateFee(context);
                }
            });
        }

    }

    @WorkerThread
    private synchronized void updateCryptoRates(Context context, List<String> currencyCodeList) {
        List<String> currencyCodeListChunks = new ArrayList<>();
        StringBuilder chunkStringBuilder = new StringBuilder();
        for (String currencyCode : currencyCodeList) {
            //check if there's enough space before appending the param.
            //code length + 1 (comma)
            if (chunkStringBuilder.length() + currencyCode.length() + 1 > FSYMS_CHAR_LIMIT) {
                //One chunk is full, add it and create new builder.
                currencyCodeListChunks.add(chunkStringBuilder.toString());
                chunkStringBuilder = new StringBuilder();
            }
            chunkStringBuilder.append(currencyCode);
            chunkStringBuilder.append(',');
        }
        currencyCodeListChunks.add(chunkStringBuilder.toString());
        for (String currencyCodeChunk : currencyCodeListChunks) {
            fetchCryptoRates(context, currencyCodeChunk);
        }
    }

    /**
     * Gets the rates from cryptocompare for the provided codeList
     *
     * @param context       The Context
     * @param codeListChunk The comma separated code list.
     */
    private synchronized void fetchCryptoRates(Context context, String codeListChunk) {
        String url = TOKEN_RATES_URL_PREFIX + codeListChunk + TOKEN_RATES_URL_SUFFIX;
        String result = urlGET(context, url);
        try {
            if (Utils.isNullOrEmpty(result)) {
                Log.e(TAG, "fetchCryptoRates: Failed to fetch");
                return;
            }

            JSONObject ratesJsonObject = new JSONObject(result);
            if (ratesJsonObject.length() == 0) {
                Log.e(TAG, "fetchCryptoRates: empty json");
                return;
            }
            if(!ratesJsonObject.has(BaseBitcoinWalletManager.BITCOIN_CURRENCY_CODE))
            {
                JSONObject jsonobject=new JSONObject();
                jsonobject.put("BTC",BaseBitcoinWalletManager.CryRate);
                ratesJsonObject.put(BaseBitcoinWalletManager.BITCOIN_CURRENCY_CODE,jsonobject);
            }
            Iterator<String> keys = ratesJsonObject.keys();
            Set<CurrencyEntity> ratesList = new LinkedHashSet<>();
            while (keys.hasNext()) {
                String currencyCode = keys.next();
                JSONObject jsonObject = ratesJsonObject.getJSONObject(currencyCode);
                //this code must be btc!
                String code = "BTC";//WalletBitcoinManager.BITCOIN_CURRENCY_CODE;
                //String code = WalletBitcoinManager.BITCOIN_CURRENCY_CODE;
                String rate = jsonObject.getString(code);
                //CurrencyEntity currencyEntity = new CurrencyEntity(code, "", Float.valueOf(rate), currencyCode);
                CurrencyEntity currencyEntity = new CurrencyEntity(WalletBitcoinManager.BITCOIN_CURRENCY_CODE, "", Float.valueOf(rate), currencyCode);
                ratesList.add(currencyEntity);
            }
            RatesRepository.getInstance(context).putCurrencyRates(ratesList);
        } catch (JSONException e) {
            BRReportsManager.reportBug(e);
            Log.e(TAG, "fetchCryptoRates: ", e);
        }
    }

    public synchronized void startTimer(Context context) {
        //set a new Timer
        if (mTimer != null) {
            return;
        }
        mTimer = new Timer();
        Log.d(TAG, "startTimer: started...");
        //initialize the TimerTask's job
        initializeTimerTask(context);

        mTimer.schedule(mTimerTask, DateUtils.SECOND_IN_MILLIS, DateUtils.MINUTE_IN_MILLIS);
    }

    public synchronized void stopTimerTask() {
        //stop the timer, if it's not already null
        if (mTimer != null) {
            mTimer.cancel();
            mTimer = null;
        }
    }

    @WorkerThread
    private static JSONArray fetchFiatRates(Context app) throws JSONException {
        //Fetch the BTC-Fiat rates
        String currentcode= WalletBitcoinManager.BITCOIN_CURRENCY_CODE;
        String url = APIClient.getBaseURL() + CURRENCY_QUERY_STRING +currentcode;
        String jsonString = urlGET(app, url);

        JSONArray jsonArray = null;

        if (jsonString == null) {
            Log.e(TAG, "fetchFiatRates: failed, response is null");
            return null;
        }
        try {
            JSONObject obj = new JSONObject(jsonString);
            jsonArray = obj.getJSONArray(BRConstants.BODY);

        } catch (JSONException ex) {
            Log.e(TAG, "fetchFiatRates: ", ex);
        }
        JSONArray result= (jsonArray == null ? backupFetchRates(app) : jsonArray);
        return FormatRate(result);
    }

    private static JSONArray FormatRate(JSONArray ja ) throws JSONException {
        ArrayList<Integer> removeArray= new ArrayList<Integer>()  ;
        if(ja!=null&&ja.length()>0) {
            JSONObject bkd = null;
            for (int i = 0; i < ja.length(); i++) {
                JSONObject jsonObject = (JSONObject) ja.get(i);
                String code = jsonObject.getString(CODE);
                if ("eth".equalsIgnoreCase(code)
                        || "xrp".equalsIgnoreCase(code)
                        || "bch".equalsIgnoreCase(code)
                        || "btc".equalsIgnoreCase(code)
                )
                    removeArray.add(i);
                String rate = String.format("%.2f", Double.valueOf(jsonObject.getString(RATE)) / WalletBitcoinManager.RATE);
                jsonObject.put(RATE, rate);

            }
            for (int i = removeArray.size() - 1; i >= 0; i--) {
                ja.remove(removeArray.get(i));
            }

            bkd = new JSONObject();
            bkd.put(CODE, WalletBitcoinManager.BITCOIN_CURRENCY_CODE);
            bkd.put(NAME, WalletBitcoinManager.NAME);
            bkd.put(RATE, Double.valueOf(1));

            ja.put(bkd);


        }

            return  ja;
    }

    /**
     * Fetches data from /currencies api meant for new icos and tokens with no public rates yet.
     *
     * @param context Context
     */
    @WorkerThread
    private static void fetchNewTokensData(Context context) {
        String url = APIClient.getBaseURL() + CURRENCIES_PATH;
        String tokenDataJsonString = urlGET(context, url);
        if (tokenDataJsonString == null || tokenDataJsonString.length() == 0) {
            Log.e(TAG, "fetchFiatRates: failed, response is null");
            return;
        }
        try {
            List<CurrencyEntity> currencyEntities = new ArrayList<>();
            JSONArray tokenDataArray = new JSONArray(tokenDataJsonString);
            for (int i = 0; i < tokenDataArray.length(); i++) {
                JSONObject tokenDataJsonObject =  tokenDataArray.getJSONObject(i);
                if (tokenDataJsonObject.has(CONTRACT_INITIAL_VALUE)) {
                    String priceInEth = tokenDataJsonObject.getString(CONTRACT_INITIAL_VALUE)
                            .replace(WalletEthManager.ETH_CURRENCY_CODE, "").trim();
                    String name = tokenDataJsonObject.getString(BRConstants.NAME);
                    String code = tokenDataJsonObject.getString(BRConstants.CODE);
                    CurrencyEntity ethCurrencyEntity =
                            new CurrencyEntity(WalletEthManager.ETH_CURRENCY_CODE, name, Float.valueOf(priceInEth), code);
                    CurrencyEntity currencyEntity = convertEthRateToBtc(context, ethCurrencyEntity);
                    currencyEntities.add(currencyEntity);
                }
            }
            RatesRepository.getInstance(context).putCurrencyRates(currencyEntities);
        } catch (JSONException | NumberFormatException ex) {
            Log.e(TAG, "fetchNewTokensData: ", ex);
        }
    }

    private static CurrencyEntity convertEthRateToBtc(Context context, CurrencyEntity currencyEntity) {
        if (currencyEntity == null) {
            return null;
        }

        CurrencyEntity ethBtcExchangeRate = RatesRepository.getInstance(context)
                .getCurrencyByCode(WalletEthManager.ETH_CURRENCY_CODE, WalletBitcoinManager.BITCOIN_CURRENCY_CODE);
        if (ethBtcExchangeRate == null) {
            Log.e(TAG, "computeCccRates: ethBtcExchangeRate is null");
            return null;
        }
        float newRate = new BigDecimal(currencyEntity.rate).multiply(new BigDecimal(ethBtcExchangeRate.rate)).floatValue();
        return new CurrencyEntity(WalletBitcoinManager.BITCOIN_CURRENCY_CODE, currencyEntity.name, newRate, currencyEntity.iso);
    }


    /**
     * uses https://bitpay.com/rates to fetch the rates as a backup in case our api is down.
     * @param context
     * @return JSONArray with rates data.
     */
    @WorkerThread
    private static JSONArray backupFetchRates(Context context) {
        String ratesJsonString = urlGET(context, BIT_PAY_URL);
        JSONArray ratesJsonArray = null;
        if (ratesJsonString != null) {
            try {
                JSONObject ratesJsonObject = new JSONObject(ratesJsonString);
                ratesJsonArray = ratesJsonObject.getJSONArray(BRConstants.DATA);
            } catch (JSONException e) {
                Log.e(TAG, "backupFetchRates: ", e);
            }
            return ratesJsonArray;
        }
        return null;
    }

    @WorkerThread
    public static String urlGET(Context app, String myURL) {
        Request.Builder builder = new Request.Builder()
                .url(myURL)
                .header(BRConstants.HEADER_CONTENT_TYPE, BRConstants.CONTENT_TYPE_JSON_CHARSET_UTF8)
                .header(BRConstants.HEADER_ACCEPT, BRConstants.CONTENT_TYPE_JSON_CHARSET_UTF8)
                .get();

        Request request = builder.build();
        String bodyText = null;
        APIClient.BRResponse resp = APIClient.getInstance(app).sendRequest(request, false);

        try {
            bodyText = resp.getBodyText();
            String strDate = resp.getHeaders().get(BRConstants.DATE);
            if (strDate == null) {
                Log.e(TAG, "urlGET: strDate is null!");
                return bodyText;
            }
            SimpleDateFormat formatter = new SimpleDateFormat(DATE_FORMAT, Locale.US);
            Date date = formatter.parse(strDate);
            long timeStamp = date.getTime();
            BRSharedPrefs.putSecureTime(app, timeStamp);
        } catch (ParseException e) {
            Log.e(TAG, "urlGET: ", e);
        }
        return bodyText;
    }

    private void fetchPriceChanges(Context context, List<String> tokenList) {
        String toCurrency = BRSharedPrefs.getPreferredFiatIso(context);
        Map<String, PriceChange> priceChanges = CurrencyHistoricalDataClient.fetch24HrsChange(context, tokenList, toCurrency);
        RatesRepository.getInstance(context).updatePriceChanges(priceChanges);
    }
}
