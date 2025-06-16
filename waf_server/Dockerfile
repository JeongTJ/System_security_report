FROM alpine:3.20

RUN apk add --no-cache build-base libevent-dev pcre2-dev
WORKDIR /src
# COPY project/waf.c ./

# RUN gcc -O2 waf.c -levent -lpcre2-8 -o waf

EXPOSE 8080
CMD ["ls", "-la"] 
# CMD ["/src/waf"] 