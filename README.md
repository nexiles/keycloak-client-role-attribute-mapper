# Keycloak client-role-attribute-mapper

This is a custom provider implementation to map client role attributes to token claims. 

Why custom? Because keycloak doesn't offer any per default.

## Usage

Copy the latest released `client-role-attribute-mapper-{version}.jar` into the `providers/` directory of
your keycloak installation and restart keycloak.

When creating a Mapper: *Add mapper* > *By configuration* > *User Client Role Attribute*
