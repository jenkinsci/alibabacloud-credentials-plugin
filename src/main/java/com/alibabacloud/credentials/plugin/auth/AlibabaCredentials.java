package com.alibabacloud.credentials.plugin.auth;

import com.alibabacloud.credentials.plugin.client.AlibabaClient;
import com.aliyuncs.auth.AlibabaCloudCredentials;
import com.aliyuncs.ecs.model.v20140526.DescribeRegionsResponse;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Extension;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

import static com.cloudbees.plugins.credentials.CredentialsScope.SYSTEM;
import static hudson.security.Permission.CREATE;
import static hudson.security.Permission.UPDATE;

import java.util.List;
import java.util.UUID;


/**
 * Created by kunlun.ykl on 2020/8/26.
 */
@NameWith(
    value = AlibabaCredentials.NameProvider.class,
    priority = 1
)
@Slf4j
public class AlibabaCredentials extends BaseStandardCredentials implements AlibabaCloudCredentials {
    private static final long serialVersionUID = -323740205079785605L;
    /**
     * 主账号的AK, 或者RamRole的临时AK
     */
    protected String accessKey;
    /**
     * 主账号的SK, 或者RamRole的临时SK
     */
    protected Secret secretKey;
    public static final String DEFAULT_ECS_REGION = "cn-beijing";

    public AlibabaCredentials(@CheckForNull String accessKey, @CheckForNull String secretKey) {
        super(CredentialsScope.GLOBAL, UUID.randomUUID().toString(), "test");
        this.accessKey = accessKey;
        this.secretKey = Secret.fromString(secretKey);
    }

    @DataBoundConstructor
    public AlibabaCredentials(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                              @CheckForNull String accessKey, @CheckForNull String secretKey,
                              @CheckForNull String description) {
        super(scope, id, description);
        this.accessKey = accessKey;
        this.secretKey = Secret.fromString(secretKey);
    }

    public AlibabaCredentials(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    public String getAccessKey() {
        return accessKey;
    }

    public Secret getSecretKey() {
        return secretKey;
    }

    public String getDisplayName() {
        return accessKey;
    }

    @Override
    public CredentialsScope getScope() {
        return SYSTEM;
    }

    @Override
    public String getAccessKeyId() {
        return accessKey;
    }

    @Override
    public String getAccessKeySecret() {
        return secretKey.getPlainText();
    }

    public void setAccessKey(String accessKey) {
        this.accessKey = accessKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = Secret.fromString(secretKey);
    }

    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Alibaba Cloud Credentials";
        }

        public  ACL getACL() {
            return Jenkins.get().getACL();
        }

        @RequirePOST
        public FormValidation doCheckSecretKey(@QueryParameter("accessKey") String accessKey,
                                               @QueryParameter String value) {
            if(!this.getACL().hasPermission(CREATE) && !getACL().hasPermission(UPDATE)){
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

            AlibabaCloudCredentials credentials = new AlibabaCredentials(accessKey, value);
            AlibabaClient client = new AlibabaClient(credentials, DEFAULT_ECS_REGION, false);
            List<DescribeRegionsResponse.Region> regions = client.describeRegions();
            if (CollectionUtils.isEmpty(regions)) {
                return FormValidation.error("Illegal ak/sk");
            }
            return FormValidation.ok();
        }
    }
}
