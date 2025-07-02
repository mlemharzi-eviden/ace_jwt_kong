FROM openjdk:17-jdk-slim

# Créer un répertoire de travail
WORKDIR /app

# Copier les sources Java
COPY JwtAuthServer.java .

# Copier les bibliothèques externes Nimbus
COPY nimbus-jose-jwt-10.3.jar .


# Compiler le fichier Java avec toutes les dépendances
RUN javac -cp ".:nimbus-jose-jwt-10.3.jar" JwtAuthServer.java

# Démarrer l'application
CMD ["java", "-cp", ".:nimbus-jose-jwt-10.3.jar", "JwtAuthServer"]