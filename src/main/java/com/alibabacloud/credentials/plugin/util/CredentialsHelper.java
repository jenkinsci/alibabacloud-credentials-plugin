package com.alibabacloud.credentials.plugin.util;

import com.alibaba.fastjson.JSON;
import com.alibabacloud.credentials.plugin.auth.AlibabaCredentials;
import com.alibabacloud.credentials.plugin.auth.AlibabaSessionTokenCredentials;
import com.aliyuncs.auth.AlibabaCloudCredentials;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider.StoreImpl;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.security.ACL;
import jenkins.model.Jenkins;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;

import javax.annotation.CheckForNull;
import java.io.IOException;
import java.util.Collections;

/**
 * Created by kunlun.ykl on 2020/8/26.
 */
@Slf4j
public class CredentialsHelper {
    private static final Long REFRESH_THRESHOLD_TIME = 300L;

    @CheckForNull
    public static AlibabaCredentials getCredentials(@CheckForNull String credentialsId) {
        if (StringUtils.isBlank(credentialsId)) {
            log.warn("getCredentials credentialsId is null, credentialsId:{}", credentialsId);
            return null;
        }
        AlibabaCredentials alibabaCredentials = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(AlibabaCredentials.class, Jenkins.get(),
                        ACL.SYSTEM, Collections.emptyList()),
                CredentialsMatchers.withId(credentialsId));
        if (alibabaCredentials == null) {
            log.warn("getCredentials alibabaCredentials is null, credentialsId:{}", credentialsId);
            return null;
        }
        // 判断是否为token模式
        if (isSessionTokenCredentials(alibabaCredentials)) {
            if (isRamTokenExpired((AlibabaSessionTokenCredentials) alibabaCredentials)) {
                return alibabaCredentials;
            }

            // 刷新token
            if (refreshRamCredentials((AlibabaSessionTokenCredentials) alibabaCredentials)) {
                log.info("refresh success. credentialsId: {}", credentialsId);
            } else {
                log.warn("refresh failed. credentialsId: {}", credentialsId);
            }
        }
        return alibabaCredentials;
    }

    public static boolean isSessionTokenCredentials(AlibabaCloudCredentials alibabaCredentials) {
        return alibabaCredentials instanceof AlibabaSessionTokenCredentials;
    }

    public static boolean isRamTokenExpired(AlibabaSessionTokenCredentials sessionTokenCredentials) {
        Long ramRefreshTime = sessionTokenCredentials.getRamRefreshTime();
        Long currentTime = sessionTokenCredentials.getCurrentTime();
        Long stsTokenDuration = sessionTokenCredentials.getStsTokenDuration();
        long l = currentTime - ramRefreshTime;
        long ll = stsTokenDuration - REFRESH_THRESHOLD_TIME;
        // （（当前时间 - 上次刷新时间）<= (token超时时间 - 设置阈值时间300)） = 未超时。反之则认为超时
        if (l <= ll) {
            log.warn("isRamTokenExpired error, regions isEmpty credentialsId:{}", sessionTokenCredentials.getId());
            return true;
        }
        return false;
    }

    public static boolean refreshRamCredentials(AlibabaSessionTokenCredentials sessionTokenCredentials) {
        AlibabaCredentials parent = sessionTokenCredentials.getParent();
        if (parent == null) {
            log.error("refreshRamCredentials error, getParent not found, sessionTokenCredentials:{}", JSON.toJSON(sessionTokenCredentials));
            return false;
        }
        try {
            // 生成新的token
            AlibabaSessionTokenCredentials replacement = new AlibabaSessionTokenCredentials(sessionTokenCredentials.getScope(),
                    sessionTokenCredentials.getId(),
                    parent.getAccessKeyId(),
                    parent.getAccessKeySecret(),
                    sessionTokenCredentials.getDescription(),
                    sessionTokenCredentials.getIamRoleArn(),
                    sessionTokenCredentials.getRoleSessionName(),
                    sessionTokenCredentials.getStsTokenDuration());
            // 修改credentials
            updateCredentials(sessionTokenCredentials, replacement);
            sessionTokenCredentials.setAccessKey(replacement.getAccessKeyId());
            sessionTokenCredentials.setSecretKey(replacement.getAccessKeySecret());
            sessionTokenCredentials.setSecretToken(replacement.getSecretToken());
            return true;
        } catch (IOException e) {
            log.error("refreshRamCredentials error, credentialsId:{}, e:{}", sessionTokenCredentials.getId(), ExceptionUtils.getStackTrace(e));
        }
        return false;
    }

    private static void updateCredentials(AlibabaSessionTokenCredentials alibabaCredentials, AlibabaSessionTokenCredentials replacement) throws IOException {
        // get credentials domain
        Domain domain = Domain.global();
        // get credentials store
        StoreImpl store = new StoreImpl();
        // add credential to store
        store.updateCredentials(domain, alibabaCredentials, replacement);
    }
}