package com.alibabacloud.credentials.plugin.client;

import com.alibaba.fastjson.JSON;
import com.alibabacloud.credentials.plugin.auth.AlibabaSessionTokenCredentials;
import com.alibabacloud.credentials.plugin.util.CredentialsHelper;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.auth.AlibabaCloudCredentials;
import com.aliyuncs.auth.sts.AssumeRoleRequest;
import com.aliyuncs.auth.sts.AssumeRoleResponse;
import com.aliyuncs.ecs.model.v20140526.DescribeKeyPairsRequest;
import com.aliyuncs.ecs.model.v20140526.DescribeKeyPairsResponse;
import com.aliyuncs.ecs.model.v20140526.DescribeRegionsRequest;
import com.aliyuncs.ecs.model.v20140526.DescribeRegionsResponse;
import com.aliyuncs.ecs.model.v20140526.DescribeRegionsResponse.Region;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.google.common.collect.Lists;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;

import javax.annotation.Nullable;
import java.util.List;

/**
 * Created by kunlun.ykl on 2020/8/26.
 */
@Slf4j
public class AlibabaClient {

    @Getter
    private IAcsClient client;
    @Getter
    private String regionNo;

    public AlibabaClient(AlibabaCloudCredentials credentials, String regionNo, boolean isVpcEnv) {
        IClientProfile profile;
        if (CredentialsHelper.isSessionTokenCredentials(credentials)) {
            profile = DefaultProfile.getProfile(regionNo,
                    credentials.getAccessKeyId(),
                    credentials.getAccessKeySecret(),
                    ((AlibabaSessionTokenCredentials) credentials).getSecretToken());
        } else {
            profile = DefaultProfile.getProfile(regionNo,
                    credentials.getAccessKeyId(),
                    credentials.getAccessKeySecret());
        }
        // 如果JenkinsMaster是在VPC内网环境下, 则使用内网域名
        if(isVpcEnv) {
            profile.enableUsingVpcEndpoint();
        }
        this.client = new DefaultAcsClient(profile);
        this.regionNo = regionNo;
        log.info("AlibabaClient init success. regionNo: {} isVpcEnv: {}", regionNo, isVpcEnv);
    }

    public AssumeRoleResponse createAssumeRoleRequest(String iamRoleArn, String roleSessionName, Long stsTokenDuration) throws ClientException {
        AssumeRoleRequest assumeRoleRequest = new AssumeRoleRequest();
        assumeRoleRequest.setMethod(com.aliyuncs.http.MethodType.POST);
        assumeRoleRequest.setAcceptFormat(FormatType.JSON);
        assumeRoleRequest.setRoleArn(iamRoleArn);
        assumeRoleRequest.setRoleSessionName(roleSessionName);
        assumeRoleRequest.setDurationSeconds(stsTokenDuration);
        return client.getAcsResponse(assumeRoleRequest);
    }

    public List<Region> describeRegions() {
        try {
            DescribeRegionsRequest request = new DescribeRegionsRequest();
            request.setSysRegionId(regionNo);
            DescribeRegionsResponse acsResponse = client.getAcsResponse(request);
            if (CollectionUtils.isEmpty(acsResponse.getRegions())) {
                return Lists.newArrayList();
            }
            return acsResponse.getRegions();
        } catch (Exception e) {
            log.error("describeRegions error.", e);
        }
        return Lists.newArrayList();
    }

    public List<DescribeKeyPairsResponse.KeyPair> describeKeyPairs(@Nullable String keyPairName, @Nullable String pfp) {
        try {
            DescribeKeyPairsRequest request = new DescribeKeyPairsRequest();
            request.setSysRegionId(regionNo);
            request.setKeyPairName(keyPairName);
            request.setKeyPairFingerPrint(pfp);
            DescribeKeyPairsResponse acsResponse = client.getAcsResponse(request);
            log.info(JSON.toJSONString(acsResponse));
            List<DescribeKeyPairsResponse.KeyPair> keyPairs = acsResponse.getKeyPairs();
            if (CollectionUtils.isEmpty(keyPairs)) {
                return Lists.newArrayList();
            }
            return keyPairs;
        } catch (Exception e) {
            log.error("listKeyPairs error", e);
        }
        return Lists.newArrayList();
    }
}
