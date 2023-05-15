package com.nexiles.keycloak;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import javax.annotation.Nullable;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.keycloak.utils.JsonUtils.splitClaimPath;

/**
 * Class for mapping of user client role attributes to an ID and Access Token claim.
 *
 * @author <a href="mailto:samuel.frei@nexiles.com">Samuel Frei</a>
 * <p>
 * Deeply inspired by:
 * @see org.keycloak.protocol.oidc.mappers.UserClientRoleMappingMapper
 * @see org.keycloak.protocol.oidc.mappers.AbstractUserRoleMappingMapper
 * @see org.keycloak.utils.RoleResolveUtil
 */
@SuppressWarnings({"unused", "JavadocReference"})
public class UserClientRoleAttributeMappingMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private final static Logger logger = Logger.getLogger(UserClientRoleAttributeMappingMapper.class);

    public static final String PROVIDER_ID = "oidc-usermodel-client-role-attribute-mapper";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    private static final String USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_CLIENT_ID = "usermodel.clientRoleAttributeMapping.clientId";
    private static final String USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_NAME = "usermodel.clientRoleAttributeMapping.clientRoleName";
    private static final String USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_ATTRIBUTE_NAME = "usermodel.clientRoleAttributeMapping.clientRoleAttributeName";

    private static final String USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_CLIENT_ID = "usermodel.clientRoleAttributeMapping.addClientId";
    private static final String USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ROLE_NAME = "usermodel.clientRoleAttributeMapping.addRoleName";
    private static final String USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ATTRIBUTE_NAME = "usermodel.clientRoleAttributeMapping.addAttributeName";
    private static final String USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ATTRIBUTE_VALUE_PREFIX = "usermodel.clientRoleAttributeMapping.attributeValuePrefix";

    static {
        final ProviderConfigProperty clientId = new ProviderConfigProperty();
        clientId.setName(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_CLIENT_ID);
        clientId.setLabel(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID_LABEL);
        clientId.setHelpText(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID_HELP_TEXT);
        clientId.setType(ProviderConfigProperty.CLIENT_LIST_TYPE);
        CONFIG_PROPERTIES.add(clientId);

        final ProviderConfigProperty clientRoleName = new ProviderConfigProperty();
        clientRoleName.setName(USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_NAME);
        clientRoleName.setLabel("Role Name");
        clientRoleName.setHelpText("Client Role Name for attribute mappings. Just client role attributes of this client role will be added to the token. If this is unset, client role attributes of all clients will be added to the token.");
        clientRoleName.setType(ProviderConfigProperty.ROLE_TYPE);
        CONFIG_PROPERTIES.add(clientRoleName);

        final ProviderConfigProperty attributeName = new ProviderConfigProperty();
        attributeName.setName(USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_ATTRIBUTE_NAME);
        attributeName.setLabel("Attribute Name");
        attributeName.setHelpText("The Attribute Name for attribute mappings. Just client role attributes with that name will be added to the token. If this is unset, all attributes of the client role will be added to the token.");
        attributeName.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(attributeName);

        final ProviderConfigProperty addClientId = new ProviderConfigProperty();
        addClientId.setName(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_CLIENT_ID);
        addClientId.setLabel("Add Client ID");
        addClientId.setHelpText("Append the Client ID to the token claim.");
        addClientId.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        addClientId.setDefaultValue("true");
        CONFIG_PROPERTIES.add(addClientId);

        final ProviderConfigProperty addRoleName = new ProviderConfigProperty();
        addRoleName.setName(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ROLE_NAME);
        addRoleName.setLabel("Add Role Name");
        addRoleName.setHelpText("Append the Client Role Name to the token claim.");
        addRoleName.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        addRoleName.setDefaultValue("true");
        CONFIG_PROPERTIES.add(addRoleName);

        final ProviderConfigProperty addAttributeName = new ProviderConfigProperty();
        addAttributeName.setName(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ATTRIBUTE_NAME);
        addAttributeName.setLabel("Add Attribute Name");
        addAttributeName.setHelpText("Append the Client Role Attribute Name to the token claim.");
        addAttributeName.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        addAttributeName.setDefaultValue("true");
        CONFIG_PROPERTIES.add(addAttributeName);

        final ProviderConfigProperty attributeValuePrefix = new ProviderConfigProperty();
        attributeValuePrefix.setName(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ATTRIBUTE_VALUE_PREFIX);
        attributeValuePrefix.setLabel("Attribute Value Prefix");
        attributeValuePrefix.setHelpText("The Attribute Value prefix for attribute mappings. Prefix all attribute values with given prefix.");
        attributeValuePrefix.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(attributeValuePrefix);

        final ProviderConfigProperty multiValued = new ProviderConfigProperty();
        multiValued.setName(ProtocolMapperUtils.MULTIVALUED);
        multiValued.setLabel(ProtocolMapperUtils.MULTIVALUED_LABEL);
        multiValued.setHelpText(ProtocolMapperUtils.MULTIVALUED_HELP_TEXT);
        multiValued.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        multiValued.setDefaultValue("true");
        CONFIG_PROPERTIES.add(multiValued);

        OIDCAttributeMapperHelper.addAttributeConfig(CONFIG_PROPERTIES, UserClientRoleAttributeMappingMapper.class);
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "User Client Role Attribute";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Map a user client role attribute to a token claim.";
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession session, ClientSessionContext clientSessionCtx) {
        final String clientId = mappingModel.getConfig().get(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_CLIENT_ID);
        final String clientRoleName = mappingModel.getConfig().get(USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_NAME);
        final String attributeName = mappingModel.getConfig().get(USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_ATTRIBUTE_NAME);

        final Set<ClientRoleAttributes> resolvedClientRoleAttributes =
                getAndCacheResolvedClientRolesAttributes(session, clientSessionCtx, clientId, clientRoleName, attributeName);

        if (resolvedClientRoleAttributes.isEmpty())
            return;

        for (final ClientRoleAttributes resolvedClientRoleAttribute : resolvedClientRoleAttributes) {
            mapClaim(token, mappingModel, resolvedClientRoleAttribute);
        }

    }

    /**
     * RegEXP obtained from {@link org.keycloak.protocol.oidc.mappers.AbstractUserRoleMappingMapper}
     */

    @SuppressWarnings("RegExpRedundantEscape")
    private static final Pattern CLIENT_ID_PATTERN = Pattern.compile("\\$\\{client_id\\}");

    private static final Pattern DOT_PATTERN = Pattern.compile("\\.");
    private static final String DOT_REPLACEMENT = "\\\\\\\\.";

    /**
     * Adjusted version of unfortunately private {@link AbstractUserRoleMappingMapper#mapClaim}.
     * <p>
     * Maps the filtered client role attributes to token claim based on configuration.
     *
     * @param token                the token to map claims to.
     * @param mappingModel         for mapper configuration access.
     * @param clientRoleAttributes the client role attributes wrapper with attributes information.
     */
    @SuppressWarnings("AssignmentToMethodParameter")
    private static void mapClaim(IDToken token, ProtocolMapperModel mappingModel,
                                 ClientRoleAttributes clientRoleAttributes) {


        String tokenClaimName = mappingModel.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
        if (tokenClaimName == null) {
            return;
        }

        String clientId = clientRoleAttributes.getClientId();

        if (clientId != null) {
            // case when clientId contains dots
            clientId = DOT_PATTERN.matcher(clientId).replaceAll(DOT_REPLACEMENT);
            tokenClaimName = CLIENT_ID_PATTERN.matcher(tokenClaimName).replaceAll(clientId);
        }

        final boolean addClientId = mappingModel.getConfig().get(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_CLIENT_ID).equals("true");
        if (addClientId) {
            tokenClaimName = tokenClaimName.concat("." + clientId);
        }

        final Set<Map.Entry<String, List<String>>> attributeEntry = clientRoleAttributes.getAttributes().entrySet();
        for (final Map.Entry<String, List<String>> entry : attributeEntry) {


            final String attributeName = entry.getKey();

            final boolean addRoleName = mappingModel.getConfig().get(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ROLE_NAME).equals("true");
            if (addRoleName) {
                tokenClaimName = tokenClaimName.concat("." + clientRoleAttributes.getRoleName());
            }

            final boolean addAttributeName = mappingModel.getConfig().get(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ATTRIBUTE_NAME).equals("true");
            if (addAttributeName) {
                tokenClaimName = tokenClaimName.concat("." + attributeName);
            }

            Object attributeValues = entry.getValue();

            final String attributeValuePrefix = mappingModel.getConfig().get(USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ATTRIBUTE_VALUE_PREFIX);
            if (attributeValuePrefix != null) {
                attributeValues = entry.getValue().stream()
                        .map(attributeValuePrefix::concat)
                        .toList();
            }

            final boolean multiValued = mappingModel.getConfig().get(ProtocolMapperUtils.MULTIVALUED).equals("true");
            if (!multiValued) {
                attributeValues = entry.getValue().toString();
            }

            logger.tracef("Map to claim (%s) - attributeName: %s addClientId: %s addRoleName: %s addAttributeName: %s multiValued: %s: %s",
                    tokenClaimName, addAttributeName, addClientId, addRoleName, addAttributeName, multiValued, attributeValues);


            mapToClaim(token, mappingModel, tokenClaimName, attributeValues);

        }

    }

    @SuppressWarnings({"AssignmentToMethodParameter", "unchecked", "rawtypes"})
    private static void mapToClaim(IDToken token, ProtocolMapperModel mappingModel, String tokenClaimName, Object claimValue) {

        claimValue = OIDCAttributeMapperHelper.mapAttributeValue(mappingModel, claimValue);
        if (claimValue == null) return;

        final List<String> split = splitClaimPath(tokenClaimName);

        final int length = split.size();
        int i = 0;
        Map<String, Object> jsonObject = token.getOtherClaims();
        for (final String component : split) {
            i++;
            if (i == length) {
                // Case when we want to add to existing set of roles
                final Object last = jsonObject.get(component);

                if (last instanceof Collection lastColl && claimValue instanceof Collection claimValueColl) {
                    lastColl.addAll(claimValueColl);
                    jsonObject.put(component, new HashSet<>(lastColl));
                } else {
                    jsonObject.put(component, claimValue);
                }

            } else {
                // Process token claim path

                Map<String, Object> nested = (Map<String, Object>) jsonObject.get(component);

                if (nested == null) {
                    nested = new HashMap<>();
                    jsonObject.put(component, nested);
                }

                jsonObject = nested;
            }
        }
    }

    private static final String RESOLVED_CLIENT_ROLES_ATTRIBUTES_ATTR = "RESOLVED_CLIENT_ROLES_ATTRIBUTES";

    /**
     * Filter client roles based on given parameter.
     *
     * @param session          the current keycloak session.
     * @param clientSessionCtx the current client session context.
     * @param clientId         the client id to filter for.
     * @param clientRoleName   the client role name to filter for.
     * @param attributeName    the attribute name to filer for.
     * @return all filtered client role attributes.
     */
    @SuppressWarnings("unchecked")
    public static Set<ClientRoleAttributes> getAndCacheResolvedClientRolesAttributes(KeycloakSession session, ClientSessionContext clientSessionCtx,
                                                                                     @Nullable String clientId, @Nullable String clientRoleName, @Nullable String attributeName) {

        final ClientModel client = clientSessionCtx.getClientSession().getClient();

        final String resolvedClientRolesAttributesAttrName = RESOLVED_CLIENT_ROLES_ATTRIBUTES_ATTR + ":" + clientSessionCtx.getClientSession().getUserSession().getId();
        final Set<ClientRoleAttributes> resolvedClientRoleAttributes = session.getAttribute(resolvedClientRolesAttributesAttrName, Set.class);

        if (resolvedClientRoleAttributes == null) {

            logger.tracef("Resolve - clientId: %s clientRoleName: %s - attributeName: %s",
                    clientId, clientRoleName, attributeName);

            final Set<ClientRoleAttributes> filteredClientRoleAttributes = clientSessionCtx.getRolesStream() // Get roles of authenticated client
                    .filter(RoleModel::isClientRole)
                    .filter(clientRole -> clientId == null || clientId.equals(clientModelForRole(clientRole).getClientId()))
                    .filter(clientRole -> clientRoleName == null || clientRoleNameEquals(clientRole, clientRoleName))
                    .filter(clientRole -> attributeName == null || clientRole.getAttributes().containsKey(attributeName))
                    .map(ClientRoleAttributes::fromRoleModel)
                    .collect(Collectors.toSet());

            logger.tracef("Filtered: %s", filteredClientRoleAttributes);

            session.setAttribute(resolvedClientRolesAttributesAttrName, filteredClientRoleAttributes);

            return filteredClientRoleAttributes;
        }

        logger.tracef("Cached: %s", resolvedClientRoleAttributes);

        return resolvedClientRoleAttributes;
    }

    /**
     * Check if equals where clientRoleName is dot delimited like: clientName.roleName.
     *
     * @param clientRole     the client role to use to check name for.
     * @param clientRoleName the dot delimited client role name.
     * @return true if the client role name matches, false if not.
     */
    private static boolean clientRoleNameEquals(RoleModel clientRole, String clientRoleName) {
        final String builtClientRoleName = String.join(".", clientModelForRole(clientRole).getClientId(), clientRole.getName());
        return clientRoleName.equals(builtClientRoleName);
    }

    /**
     * Get and cast the client model for role model. Role model should be
     * already checked before.
     *
     * @param roleModel the role model to get client for.
     * @return the client model.
     */
    private static ClientModel clientModelForRole(RoleModel roleModel) {
        return (ClientModel) roleModel.getContainer();
    }

    /**
     * Simple wrapper to bundle client > role > attributes information.
     */
    @Getter
    @RequiredArgsConstructor
    private static class ClientRoleAttributes {

        private final String clientId;

        private final String roleName;

        private final Map<String, List<String>> attributes;

        static ClientRoleAttributes fromRoleModel(RoleModel roleModel) {
            return new ClientRoleAttributes(
                    clientModelForRole(roleModel).getClientId(),
                    roleModel.getName(),
                    roleModel.getAttributes()
            );
        }

        @Override
        public String toString() {
            return String.format("(clientId: '%s' roleName: '%s' - attributes: %s)", clientId, roleName, attributes);
        }

    }

}
