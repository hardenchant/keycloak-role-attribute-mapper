package eu.bindworks.keycloak.roleattribmapper;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RoleAttributeMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    public static final String PROVIDER_ID = "oidc-role-attribute-mapper";
    private static final List<ProviderConfigProperty> configProperties;

    private static final String PROPERTY_ROLE_ATTRIBUTE = "attribute";

    static {
        configProperties = new ArrayList<>();

        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID);
        property.setLabel(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID_LABEL);
        property.setHelpText(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID_HELP_TEXT);
        property.setType(ProviderConfigProperty.CLIENT_LIST_TYPE);
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(PROPERTY_ROLE_ATTRIBUTE);
        property.setLabel("Role attribute name");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Name of the role attribute");
        configProperties.add(property);

        OIDCAttributeMapperHelper.addAttributeConfig(configProperties, RoleAttributeMapper.class);

        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.MULTIVALUED);
        property.setLabel(ProtocolMapperUtils.MULTIVALUED_LABEL);
        property.setHelpText(ProtocolMapperUtils.MULTIVALUED_HELP_TEXT);
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.AGGREGATE_ATTRS);
        property.setLabel(ProtocolMapperUtils.AGGREGATE_ATTRS_LABEL);
        property.setHelpText(ProtocolMapperUtils.AGGREGATE_ATTRS_HELP_TEXT);
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Role Attribute";
    }

    @Override
    public String getHelpText() {
        return "Map a custom role attribute to a token claim";
    }

    private Stream<RoleModel> getUserRolesStream(RealmModel realm, UserModel user, String clientId) {
        Stream<RoleModel> roles = clientId == null
                ? realm.getRolesStream()
                : realm.getClientByClientId(clientId).getRolesStream();

        return roles.filter(user::hasRole);
    }

    private List<String> resolveAttribute(RoleModel role, String name) {
        return role.getAttributeStream(name).collect(Collectors.toList());
    }

    private Collection<String> resolveAttribute(RealmModel realm, UserModel user, String clientId, String name, boolean aggregateAttrs) {
        Stream<List<String>> attributes = getUserRolesStream(realm, user, clientId)
                .map((group) -> resolveAttribute(group, name))
                .filter(Objects::nonNull)
                .filter((attr) -> !attr.isEmpty());

        if (!aggregateAttrs) {
            return attributes.findFirst().orElse(null);
        } else {
            return attributes.flatMap(Collection::stream).collect(Collectors.toSet());
        }
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        String attributeName = mappingModel.getConfig().get(PROPERTY_ROLE_ATTRIBUTE);
        boolean aggregateAttrs = Boolean.parseBoolean(mappingModel.getConfig().get(ProtocolMapperUtils.AGGREGATE_ATTRS));
        String clientId = mappingModel.getConfig().get(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID);
        Collection<String> attributeValue = resolveAttribute(userSession.getRealm(), user, clientId, attributeName, aggregateAttrs);
        if (attributeValue == null) return;
        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, attributeValue);
    }
}
