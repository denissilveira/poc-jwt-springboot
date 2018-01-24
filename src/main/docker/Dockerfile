FROM java:8
MAINTAINER Denis Silveira<denis.rayan@gmail.com>
VOLUME /tmp
ADD poc-jwt-springboot-1.0.0.jar pocjwt.jar
RUN bash -c 'touch /pocjwt.jar'
ENTRYPOINT ["java","-Dspring.profiles.active=docker","-jar","/pocjwt.jar"]
