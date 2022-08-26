package com.alibabacloud.credentials.plugin.auth;

import com.alibabacloud.credentials.plugin.client.AlibabaClient;
import com.aliyuncs.auth.sts.AssumeRoleResponse;
import com.aliyuncs.ecs.model.v20140526.DescribeRegionsResponse;
import com.aliyuncs.exceptions.ClientException;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Extension;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static hudson.security.Permission.CREATE;
import static hudson.security.Permission.UPDATE;

/**
 * @author gaojiahao wb511401
 * @description
 * @date 2022/8/16 下午5:56
 */
@Slf4j
public class AlibabaSessionTokenCredentials extends AlibabaCredentials implements AlibabaCloudRamCredentials {

    private static final long serialVersionUID = -4185406790852698614L;

    private String secretToken;

    private String iamRoleArn;

    private String roleSessionName;

    // token持续时间
    private Long stsTokenDuration;

    // token上次刷新时间
    private Long ramRefreshTime;

    public static final Long STS_CREDENTIALS_DURATION_SECONDS = 3600L;

    private AlibabaCredentials parent;

    public static final String DEFAULT_ECS_REGION = "cn-beijing";

    public AlibabaSessionTokenCredentials(String accessKey, String secretKey, String securityToken) {
        super(CredentialsScope.GLOBAL, UUID.randomUUID().toString(), "test");
        this.accessKey = accessKey;
        this.secretKey = Secret.fromString(secretKey);
        this.secretToken = securityToken;
    }

    @DataBoundConstructor
    public AlibabaSessionTokenCredentials(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                              @CheckForNull String parentAccessKey,@CheckForNull String parentSecretKey,
                              @CheckForNull String description, @CheckForNull String iamRoleArn,
                              @CheckForNull String roleSessionName, @CheckForNull Long stsTokenDuration) {
        super(scope, id, description);
        this.parent = new AlibabaCredentials(parentAccessKey, parentSecretKey);
        this.iamRoleArn = iamRoleArn;
        this.roleSessionName = roleSessionName;
        this.stsTokenDuration = stsTokenDuration;
        readResolve();
    }



    protected Object readResolve() {
        AlibabaClient alibabaClient = new AlibabaClient(parent, DEFAULT_ECS_REGION, false);
        try {
            AssumeRoleResponse assumeRoleRequest = alibabaClient.createAssumeRoleRequest(iamRoleArn, roleSessionName, stsTokenDuration);
            this.accessKey = assumeRoleRequest.getCredentials().getAccessKeyId();
            this.secretKey = Secret.fromString(assumeRoleRequest.getCredentials().getAccessKeySecret());
            this.secretToken = assumeRoleRequest.getCredentials().getSecurityToken();
            this.ramRefreshTime = getCurrentTime();
        } catch (ClientException e) {
            log.error("createAssumeRoleRequest error, e:{}", ExceptionUtils.getStackTrace(e));
        }
        return this;
    }

    public String getParentAccessKey(){
        return parent.getAccessKeyId();
    }

    public String getParentSecretKey(){
        return parent.getAccessKeySecret();
    }

    /**
     * 获取当前时间，单位秒
     * @return Long
     */
    public Long getCurrentTime (){
        Date date = new Date();
        return date.getTime() / 1000;
    }

    public Long getRamRefreshTime() {
        return ramRefreshTime;
    }

    public void setSecretToken(String secretToken) {
        this.secretToken = secretToken;
    }

    public String getIamRoleArn() {
        return iamRoleArn;
    }

    public String getRoleSessionName() {
        return roleSessionName;
    }

    public Long getStsTokenDuration() {
        return stsTokenDuration == null ? DescriptorImpl.DEFAULT_STS_TOKEN_DURATION : stsTokenDuration;
    }

    public AlibabaCredentials getParent() {
        return parent;
    }


    public String getSecretToken() {
        return secretToken;
    }

    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Alibaba SessionToken Cloud Credentials";
        }

        public ACL getACL() {
            return Jenkins.get().getACL();
        }

        public static final Long DEFAULT_STS_TOKEN_DURATION = STS_CREDENTIALS_DURATION_SECONDS;

        @RequirePOST
        public FormValidation doCheckParentSecretKey(@QueryParameter("parentAccessKey") String accessKey,
                                               @QueryParameter("iamRoleArn") String iamRoleArn,
                                               @QueryParameter("roleSessionName") String roleSessionName,
                                               @QueryParameter("stsTokenDuration") Long stsTokenDuration,
                                               @QueryParameter String value) {
            if (!this.getACL().hasPermission(CREATE) && !getACL().hasPermission(UPDATE)) {
                return FormValidation.error("permission is error");
            }

            if (StringUtils.isBlank(accessKey) && StringUtils.isBlank(value)) {
                return FormValidation.ok();
            }
            if (StringUtils.isBlank(accessKey)) {
                return FormValidation.error("Illegal Access Key");
            }
            if (StringUtils.isBlank(value)) {
                return FormValidation.error("Illegal Secret Key");
            }

            AlibabaCredentials credentials = new AlibabaCredentials(accessKey, value);
            AlibabaClient client = new AlibabaClient(credentials, DEFAULT_ECS_REGION, false);
            // If iamRoleArn is specified, swap out the credentials.
            if (!StringUtils.isBlank(iamRoleArn)) {
                try {
                    AssumeRoleResponse acsResponse = client.createAssumeRoleRequest(iamRoleArn, roleSessionName, stsTokenDuration);
                    AlibabaCloudRamCredentials alibabaSessionTokenCredentials = new AlibabaSessionTokenCredentials(
                            acsResponse.getCredentials().getAccessKeyId(),
                            acsResponse.getCredentials().getAccessKeySecret(),
                            acsResponse.getCredentials().getSecurityToken());
                    client = new AlibabaClient(alibabaSessionTokenCredentials, DEFAULT_ECS_REGION, false);
                } catch (Exception e) {
                    log.error("Unable to assume role [" + iamRoleArn + "] with request。" + e);
                    return FormValidation.error("Unable to assume role [" + iamRoleArn + "] with request。" + e);
                }
            }
            List<DescribeRegionsResponse.Region> regions = client.describeRegions();
            if (CollectionUtils.isEmpty(regions)) {
                return FormValidation.error("Illegal ak/sk");
            }
            return FormValidation.ok();
        }

    }
}