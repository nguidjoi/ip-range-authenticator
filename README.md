# ip-authenticator

Keycloak Java Authenticator to check that user network is trusted, if trusted network check is mandatory for this user.


## build

To build the project execute the following command:

```bash
mvn package
```

## deploy

And then, assuming `$KEYCLOAK_HOME` is pointing to you Keycloak installation, just copy it into deployments directory or provider directory depending of your keycloak distribution.
 
```bash
For Quarkus distribution
    cp target/keycloak-ip-authenticator.jar $KEYCLOAK_HOME/providers/
    kc.sh build 

For Wildfly distribution
    cp target/keycloak-ip-authenticator.jar $KEYCLOAK_HOME/standalone/deployments/
```
