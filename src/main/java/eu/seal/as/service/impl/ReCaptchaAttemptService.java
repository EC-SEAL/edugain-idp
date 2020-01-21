/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service.impl;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Service;

/**
 *
 * @author nikos
 */

@Service("reCaptchaAttemptService")
public class ReCaptchaAttemptService {
    private final int MAX_ATTEMPT = 4;
    private LoadingCache<String, Integer> attemptsCache;

    public ReCaptchaAttemptService() {
        super();
        attemptsCache = CacheBuilder.newBuilder().expireAfterWrite(4, TimeUnit.HOURS).build(new CacheLoader<String, Integer>() {
            @Override
            public Integer load(final String key) {
                return 0;
            }
        });
    }

    public void reCaptchaSucceeded(final String key) {
        attemptsCache.invalidate(key);
    }

    public void reCaptchaFailed(final String key) {
        int attempts = attemptsCache.getUnchecked(key);
        attempts++;
        attemptsCache.put(key, attempts);
    }

    public boolean isBlocked(final String key) {
        return attemptsCache.getUnchecked(key) >= MAX_ATTEMPT;
    }
}
