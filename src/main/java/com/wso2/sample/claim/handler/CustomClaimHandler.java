package com.wso2.sample.claim.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.claim.mgt.ClaimManagementException;
import org.wso2.carbon.claim.mgt.ClaimManagerHandler;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.claims.impl.DefaultClaimHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * This class should be configured in IS_HOME/repository/conf/security/application-authentication.xml at
 * ApplicationAuthentication.Extensions.ClaimHandler after putting at components/lib, to be effective.
 */
public class CustomClaimHandler extends DefaultClaimHandler {

    private static Log log = LogFactory.getLog(CustomClaimHandler.class);
    private static volatile CustomClaimHandler instance;
    private String connectionURL = null;
    private String userName = null;
    private String password = null;
    private String jdbcDriver = null;
    private String sql = null;


    public static CustomClaimHandler getInstance() {
        if (instance == null) {
            synchronized (CustomClaimHandler.class) {
                if (instance == null) {
                    instance = new CustomClaimHandler();
                }
            }
        }
        return instance;
    }

    /**
     *
     */
    public Map<String, String> handleClaimMappings(StepConfig stepConfig,
                                                   AuthenticationContext context, Map<String, String> remoteClaims,
                                                   boolean isFederatedClaims) throws FrameworkException {

        if (log.isDebugEnabled()) {
            logInput(remoteClaims, isFederatedClaims);
        }

        ApplicationConfig appConfig = context.getSequenceConfig().getApplicationConfig();
        String spStandardDialect = getStandardDialect(context.getRequestType(), appConfig);
        Map<String, String> returningClaims = null;
        if (isFederatedClaims) {

            returningClaims = handleFederatedClaims(remoteClaims, spStandardDialect, stepConfig, context);

        } else {

            returningClaims = handleLocalClaims(spStandardDialect, stepConfig, context);
            Map<String, String> authenticatedUserClaims = getClaimsFromAuthenticatedUser(spStandardDialect,
                    stepConfig, context);
            if (authenticatedUserClaims.size() > 0 && returningClaims != null) {
                returningClaims.putAll(authenticatedUserClaims);
            }

        }
        if (log.isDebugEnabled()) {
            logOutput(returningClaims, context);
        }
        return returningClaims;
    }

    private Map<String, String> getClaimsFromAuthenticatedUser(String
                                                                       spStandardDialect, StepConfig stepConfig, AuthenticationContext context) throws FrameworkException {


        ApplicationConfig appConfig = context.getSequenceConfig().getApplicationConfig();
        ServiceProvider serviceProvider = appConfig.getServiceProvider();
        ClaimConfig claimConfig = serviceProvider.getClaimConfig();
        boolean isLocalClaimDialect = claimConfig.isLocalClaimDialect();

        Map<String, String> spToLocalClaimMappings = appConfig.getClaimMappings();
        if (spToLocalClaimMappings == null) {
            spToLocalClaimMappings = new HashMap<String, String>();
        }

        Map<String, String> carbonToStandardClaimMapping = new HashMap<String, String>();
        Map<String, String> requestedClaimMappings = appConfig.getRequestedClaimMappings();
        if (requestedClaimMappings == null) {
            requestedClaimMappings = new HashMap<String, String>();
        }

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(stepConfig, context);

        String tenantDomain = authenticatedUser.getTenantDomain();
        String tenantAwareUserName = authenticatedUser.getUserName();


        // key:value -> carbon_dialect:claim_value
        Map<String, String> allLocalClaims = getClaimsFromMappings(authenticatedUser.getUserAttributes());

        // If default dialect -> all non-null user claims
        // If custom dialect -> all non-null user claims that have been mapped to custom claims
        // key:value -> sp_dialect:claim_value
        Map<String, String> allSPMappedClaims = new HashMap<String, String>();

        // Requested claims only
        // key:value -> sp_dialect:claim_value
        Map<String, String> spRequestedClaims = new HashMap<String, String>();

        // if standard dialect get all claim mappings from standard dialect to carbon dialect
        spToLocalClaimMappings = getStanderDialectToCarbonMapping(spStandardDialect, context, spToLocalClaimMappings,
                tenantDomain);
        if (StringUtils.isNotBlank(spStandardDialect) && (!StringUtils.equals(spStandardDialect, ApplicationConstants
                .LOCAL_IDP_DEFAULT_CLAIM_DIALECT))) {
            carbonToStandardClaimMapping = getCarbonToStandardDialectMapping(spStandardDialect, context,
                    spToLocalClaimMappings, tenantDomain);
            requestedClaimMappings = mapRequestClaimsInStandardDialect(requestedClaimMappings,
                    carbonToStandardClaimMapping);
        }

        mapSPClaimsAndFilterRequestedClaims(spToLocalClaimMappings, requestedClaimMappings, allLocalClaims,
                allSPMappedClaims, spRequestedClaims);


        if (FrameworkConstants.RequestType.CLAIM_TYPE_OPENID.equals(context.getRequestType())) {
            spRequestedClaims = allSPMappedClaims;
        }
        return spRequestedClaims;
    }


    private void logInput(Map<String, String> remoteClaims, boolean isFederatedClaims) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        if (remoteClaims != null) {
            for (Map.Entry<String, String> entry : remoteClaims.entrySet()) {
                sb.append(entry.getKey());
                sb.append(":");
                sb.append(entry.getValue());
                sb.append(",");
            }
        }
        sb.append("]");
        log.debug("Executing claim handler. isFederatedClaims = " + isFederatedClaims +
                " and remote claims = " + sb.toString());
    }

    private void logOutput(Map<String, String> returningClaims, AuthenticationContext context) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (Map.Entry<String, String> entry : returningClaims.entrySet()) {
            sb.append(entry.getKey());
            sb.append(":");
            sb.append(entry.getValue());
            sb.append(",");
        }
        sb.append("]");
        log.debug("Returning claims from claim handler = " + sb.toString());
        Map<String, String> claimsProperty = (Map<String, String>)
                context.getProperty(FrameworkConstants.UNFILTERED_IDP_CLAIM_VALUES);
        if (claimsProperty != null) {
            sb = new StringBuilder();
            sb.append("[");
            for (Map.Entry<String, String> entry : claimsProperty.entrySet()) {
                sb.append(entry.getKey());
                sb.append(":");
                sb.append(entry.getValue());
                sb.append(",");
            }
            sb.append("]");
        }
        log.debug(FrameworkConstants.UNFILTERED_IDP_CLAIM_VALUES +
                " map property set to " + sb.toString());
        claimsProperty = (Map<String, String>)
                context.getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);
        if (claimsProperty != null) {
            sb = new StringBuilder();
            sb.append("[");
            for (Map.Entry<String, String> entry : claimsProperty.entrySet()) {
                sb.append(entry.getKey());
                sb.append(":");
                sb.append(entry.getValue());
                sb.append(",");
            }
            sb.append("]");
        }
        log.debug(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES +
                " map property set to " + sb.toString());
        claimsProperty = (Map<String, String>)
                context.getProperty(FrameworkConstants.UNFILTERED_SP_CLAIM_VALUES);
        if (claimsProperty != null) {
            sb = new StringBuilder();
            sb.append("[");
            for (Map.Entry<String, String> entry : claimsProperty.entrySet()) {
                sb.append(entry.getKey());
                sb.append(":");
                sb.append(entry.getValue());
                sb.append(",");
            }
            sb.append("]");
        }
        log.debug(FrameworkConstants.UNFILTERED_SP_CLAIM_VALUES +
                " map property set to " + sb.toString());
    }

    private AuthenticatedUser getAuthenticatedUser(StepConfig stepConfig, AuthenticationContext context) {
        AuthenticatedUser authenticatedUser;
        if (stepConfig != null) {
            //calling from StepBasedSequenceHandler
            authenticatedUser = stepConfig.getAuthenticatedUser();
        } else {
            //calling from RequestPathBasedSequenceHandler
            authenticatedUser = context.getSequenceConfig().getAuthenticatedUser();
        }
        return authenticatedUser;
    }

    private Map<String, String> getStanderDialectToCarbonMapping(String spStandardDialect,
                                                                 AuthenticationContext context,
                                                                 Map<String, String> spToLocalClaimMappings,
                                                                 String tenantDomain) throws FrameworkException {
        if (spStandardDialect != null) {
            try {
                spToLocalClaimMappings = getClaimMappings(spStandardDialect, null,
                        context.getTenantDomain(), false);
            } catch (Exception e) {
                throw new FrameworkException("Error occurred while getting all claim mappings from " +
                        spStandardDialect + " dialect to " +
                        ApplicationConstants.LOCAL_IDP_DEFAULT_CLAIM_DIALECT + " dialect for " +
                        tenantDomain + " to handle local claims", e);
            }
        }
        return spToLocalClaimMappings;
    }

    private Map<String, String> getClaimMappings(String otherDialect, Set<String> keySet,
                                                 String tenantDomain, boolean useLocalDialectAsKey)
            throws FrameworkException {

        Map<String, String> claimMapping = null;
        try {
            claimMapping = ClaimManagerHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(otherDialect, keySet, tenantDomain,
                            useLocalDialectAsKey);
        } catch (ClaimManagementException e) {
            throw new FrameworkException("Error while loading mappings.", e);
        }

        if (claimMapping == null) {
            claimMapping = new HashMap<String, String>();
        }

        return claimMapping;
    }


    private Map<String, String> getCarbonToStandardDialectMapping(String spStandardDialect,
                                                                  AuthenticationContext context,
                                                                  Map<String, String> spToLocalClaimMappings,
                                                                  String tenantDomain) throws FrameworkException {
        if (spStandardDialect != null) {
            try {
                spToLocalClaimMappings = getClaimMappings(spStandardDialect, null,
                        context.getTenantDomain(), true);
            } catch (Exception e) {
                throw new FrameworkException("Error occurred while getting all claim mappings from " +
                        ApplicationConstants.LOCAL_IDP_DEFAULT_CLAIM_DIALECT + " dialect to " +
                        spStandardDialect + " dialect for " +
                        tenantDomain + " to handle local claims", e);
            }
        }
        return spToLocalClaimMappings;
    }

    private void mapSPClaimsAndFilterRequestedClaims(Map<String, String> spToLocalClaimMappings,
                                                     Map<String, String> requestedClaimMappings,
                                                     Map<String, String> allLocalClaims,
                                                     Map<String, String> allSPMappedClaims,
                                                     Map<String, String> spRequestedClaims) {
        for (Map.Entry<String, String> entry : spToLocalClaimMappings.entrySet()) {
            String spClaimURI = entry.getKey();
            String localClaimURI = entry.getValue();
            String claimValue = allLocalClaims.get(localClaimURI);
            if (claimValue != null) {
                allSPMappedClaims.put(spClaimURI, claimValue);
                if (requestedClaimMappings.get(spClaimURI) != null) {
                    spRequestedClaims.put(spClaimURI, claimValue);
                }
            }
        }
    }

    private Map<String, String> mapRequestClaimsInStandardDialect(Map<String, String> requestedClaimMappings, Map<String, String> carbonToStandardClaimMapping) {
        Map<String, String> requestedClaimMappingsInStandardDialect = new HashMap<String, String>();
        if (requestedClaimMappings != null) {
            Iterator iterator = requestedClaimMappings.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, String> mapping = (Map.Entry) iterator.next();
                String standardMappedClaim = carbonToStandardClaimMapping.get(mapping.getValue());
                if (StringUtils.isNotBlank(standardMappedClaim)) {
                    requestedClaimMappingsInStandardDialect.put(standardMappedClaim, mapping.getValue());
                }
            }
        }
        return requestedClaimMappingsInStandardDialect;
    }

    private Map<String, String> getClaimsFromMappings(Map<ClaimMapping, String> userAttributes) {
        Map<String, String> results = new HashMap<String, String>();

        if (userAttributes != null) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                if (entry.getKey() != null && entry.getKey() instanceof ClaimMapping) {
                    ClaimMapping claimMapping = (ClaimMapping) entry.getKey();
                    Claim claim = claimMapping.getLocalClaim();
                    if (claim != null && StringUtils.isNotBlank(claim.getClaimUri())) {
                        results.put(claim.getClaimUri(), entry.getValue());
                    }
                }
            }
        }
        return results;
    }
}
