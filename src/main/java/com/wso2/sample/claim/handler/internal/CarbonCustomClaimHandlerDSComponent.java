package com.wso2.sample.claim.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
* @scr.component name="carbon.custom.claim.handler.dscomponent" immediate="true"
* @scr.reference name="user.realmservice.default"
*                interface="org.wso2.carbon.user.core.service.RealmService"
*                cardinality="1..1" policy="dynamic" bind="setRealmService"
*                unbind="unsetRealmService"
* @scr.reference name="registry.service"
*                interface="org.wso2.carbon.registry.core.service.RegistryService"
*                cardinality="1..1" policy="dynamic" bind="setRegistryService"
*                unbind="unsetRegistryService"
*/
public class CarbonCustomClaimHandlerDSComponent {
    private static Log log = LogFactory.getLog(CarbonCustomClaimHandlerDSComponent.class);
    private static RealmService realmService;
    private static RegistryService registryService;

    protected void activate(ComponentContext ctxt) {
        try {
            log.info("Carbon Custom Claim Handler activated successfully.");
        } catch (Exception e) {
            log.error("Failed to activate Carbon Custom Claim Handler ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Carbon Custom Claim Handler is deactivated ");
        }
    }

    protected void setRealmService(RealmService realmService) {
        CarbonCustomClaimHandlerDSComponent.realmService = realmService;
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the Carbon Custom Claim Handler bundle");
        }

    }

    protected void unsetRealmService(RealmService realmService) {
        CarbonCustomClaimHandlerDSComponent.realmService = null;
        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the Carbon Custom Claim Handler bundle");
        }

    }

    public static RealmService getRealmService() {
        return CarbonCustomClaimHandlerDSComponent.realmService;
    }

    protected void setRegistryService(RegistryService registryService) {
        CarbonCustomClaimHandlerDSComponent.registryService = registryService;
        if (log.isDebugEnabled()) {
            log.debug("RegistryService is set in the Carbon Custom Claim Handler bundle");
        }

    }

    protected void unsetRegistryService(RegistryService registryService) {
        CarbonCustomClaimHandlerDSComponent.registryService = null;
        if (log.isDebugEnabled()) {
            log.debug("RegistryService is unset in the Carbon Custom Claim Handler bundle");
        }

    }

    public static RegistryService getRegistryService() {
        return CarbonCustomClaimHandlerDSComponent.registryService;
    }

}
