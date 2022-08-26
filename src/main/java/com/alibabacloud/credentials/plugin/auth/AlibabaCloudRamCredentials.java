package com.alibabacloud.credentials.plugin.auth;

import com.aliyuncs.auth.AlibabaCloudCredentials;

/**
 * 子账号可以使用该类
 */
public interface AlibabaCloudRamCredentials extends AlibabaCloudCredentials {
    String getSecretToken();
}
