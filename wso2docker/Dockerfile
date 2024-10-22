# Usa la imagen oficial de WSO2 Identity Server
FROM wso2/wso2is:latest

# Directorio donde se copia el archivo JAR
ARG WSO2_SERVER_HOME=/home/wso2carbon/wso2is-5.11.0

# Copiar el archivo JAR al contenedor
COPY org.wso2.custom.userstore.manager-1.0-SNAPSHOT.jar ${WSO2_SERVER_HOME}/repository/components/dropins/

# Copiar el archivo de configuración modificado al contenedor
COPY deployment.toml ${WSO2_SERVER_HOME}/repository/conf/

# Exponer el puerto si es necesario
EXPOSE 9443

# Comando de inicio (esto normalmente ya está en la imagen base, puedes omitirlo)
CMD ["sh", "-c", "${WSO2_SERVER_HOME}/bin/wso2server.sh"]
