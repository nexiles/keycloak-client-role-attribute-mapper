package com.nexiles.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.IDToken;
import org.keycloak.utils.JsonUtils;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserClientRoleAttributeMappingMapperTest {


    @Test
    void mapClaimWithSingleAttribute(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        final String tokenClaimName = "rules";
        final String attributeName = "attr1";
        final String roleName = "rolename";

        Map<String, Object> claimStore = new HashMap<>();
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        Map<String, String> config = Map.of(
                OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "rules",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_CLIENT_ID, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ATTRIBUTE_NAME, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ROLE_NAME, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_NAME, roleName,
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_ATTRIBUTE_NAME, attributeName
        );
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        UserClientRoleAttributeMappingMapper.ClientRoleAttributes clientRoleAttributes = new UserClientRoleAttributeMappingMapper.ClientRoleAttributes(
                "clientid",
                roleName,
                parseJsonObject("{\"attr1\":[\"attr1value1\"]}")
        );
        UserClientRoleAttributeMappingMapper.mapClaim(token, mappingModel, clientRoleAttributes);

        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("attr1value1", traverseClaimMap(claims, tokenClaimName + ".clientid.rolename." + attributeName));
    }

    @Test
    void mapClaimWithMultipleAttributes(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        final String tokenClaimName = "rules";
        final String attributeName = "attr1";
        final String roleName = "rolename";

        Map<String, Object> claimStore = new HashMap<>();
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        Map<String, String> config = Map.of(
                OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "rules",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_CLIENT_ID, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ATTRIBUTE_NAME, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ROLE_NAME, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_NAME, roleName,
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_ATTRIBUTE_NAME, attributeName
        );
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        UserClientRoleAttributeMappingMapper.ClientRoleAttributes clientRoleAttributes = new UserClientRoleAttributeMappingMapper.ClientRoleAttributes(
                "clientid",
                roleName,
                parseJsonObject("{\"attr1\":[\"attr1value1\",\"attr1value2\"]}")
        );
        UserClientRoleAttributeMappingMapper.mapClaim(token, mappingModel, clientRoleAttributes);

        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("attr1value1", traverseClaimMap(claims, tokenClaimName + ".clientid.rolename." + attributeName));
    }

    private <T> Map<String,T> parseJsonObject(String json) {
        ObjectMapper mapper = new ObjectMapper();
        TypeReference<HashMap<String, T>> typeRef = new TypeReference<>(){};
        try {
            return mapper.readValue(json, typeRef);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private Object traverseClaimMap(Map<String,Object> claims, List<String> claimPathParts) {
        if(claims == null) throw new IllegalArgumentException("claims");
        String part = claimPathParts.remove(0);
        if(claimPathParts.isEmpty()) {
            // end of path
            return claims.get(part);
        }
        Object o = claims.get(part);
        if(o == null)
            throw new RuntimeException(String.format("invalid path %s", String.join(".", claimPathParts)));
        if(o instanceof Map)
            return traverseClaimMap((Map<String,Object>)o, claimPathParts);

        throw new RuntimeException(String.format("invalid value at path %s %s", String.join(".", claimPathParts), o));
    }

    private Object traverseClaimMap(Map<String,Object> claims, String path) {
        List<String> claimPathParts = JsonUtils.splitClaimPath(path);
        return traverseClaimMap(claims, claimPathParts);
    }

    @Test
    void mapToClaim(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        HashMap<String, Object> claimStore = new HashMap<>();
        when(token.getOtherClaims()).then((Answer<Map<String, Object>>) invocationOnMock -> claimStore);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("1 == 1", traverseClaimMap(claims, tokenClaimName));
    }

    @Test
    void mapToClaimWithExistingStringClaimWithMultivalued(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":\"2 == 2\"}}}");
        Map<String, String> config = Map.of(ProtocolMapperUtils.MULTIVALUED, "true");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertArrayEquals(new String[]{"2 == 2", "1 == 1"}, ((ArrayList<String>)traverseClaimMap(claims, tokenClaimName)).toArray());
    }

    @Test
    void mapToClaimWithExistingListClaimWithMultivalued(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":[\"3 == 3\",\"2 == 2\"]}}}");
        Map<String, String> config = Map.of(ProtocolMapperUtils.MULTIVALUED, "true");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertArrayEquals(new String[]{"3 == 3", "2 == 2", "1 == 1"}, ((ArrayList<String>)traverseClaimMap(claims, tokenClaimName)).toArray());
    }

    @Test
    void mapToClaimWithExistingStringClaim(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":\"2 == 2\"}}}");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("1 == 1", traverseClaimMap(claims, tokenClaimName));
    }

    @Test
    void mapToClaimWithExistingListClaim(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":[\"3 == 3\",\"2 == 2\"]}}}");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("1 == 1", traverseClaimMap(claims, tokenClaimName));
    }

    @Test
    void mapToClaimWithExistingListClaimAndArrayClaimValue(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":[\"3 == 3\",\"2 == 2\"]}}}");
        Map<String, String> config = Map.of(ProtocolMapperUtils.MULTIVALUED, "true");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = Arrays.asList("1 == 1", "0 == 0");

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertArrayEquals(new String[]{"3 == 3", "2 == 2", "1 == 1", "0 == 0"}, ((ArrayList<String>)traverseClaimMap(claims, tokenClaimName)).toArray());
    }
}