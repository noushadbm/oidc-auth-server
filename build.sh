docker build -t oidc-auth-server .
docker tag oidc-auth-server noushadbm/oidc-auth-server:latest
docker push noushadbm/oidc-auth-server:latest
