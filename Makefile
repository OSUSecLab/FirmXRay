JAR_PKG = FirmXRay.jar

MAIN = main.Main

JAVA = java

JAVAC = javac

JAR = jar
	
JFLAGS = -encoding UTF-8

	
Default: build
	
	
build: 
	$(JAVAC) -cp "lib/*" -d out @target.txt

rebuild: clean build
	
.PHONY: new clean run jar
	
new:
	mkdir -pv src out
	
clean:
	rm -frv out/* \
    rm $(JAR_PKG)

run:
	$(JAVA) -cp out:lib/ghidra.jar:lib/json.jar $(MAIN) $(PATH) $(MCU)
	
jar:
	$(JAR) -cp "lib/*" cvfe $(JAR_PKG) $(MAIN) -C out .
