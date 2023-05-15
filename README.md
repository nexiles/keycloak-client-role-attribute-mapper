# Keycloak client-role-attribute-mapper

This is a custom provider implementation to map client role attributes to token claims. 

Why custom? Because Keycloak doesn't offer any per default.

**Note:** This is currently developed and tested using **Keycloak 21**

## Usage

Copy the latest released `client-role-attribute-mapper-{version}.jar` into the `providers/` directory of
your Keycloak installation and restart Keycloak.

When creating a Mapper: *Add mapper* > *By configuration* > *User Client Role Attribute*

## Build

Use *Java 17 (`skd env`)* and hit:

```bash
mvn package
```
