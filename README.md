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

## Additional

This is made because we wanted to use RabbitMQ with OAuth2 and the JWT, but mapping realm roles to scopes seemed not
as the best solution, and we liked to stick to client roles.

## Screenshots

![Mapper Configuration](./assets/mapper-configuration.png)
