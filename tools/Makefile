all: ../images/packet.svg

BITFIELDD=node_modules/bit-field
BITFIELD=$(BITFIELDD)/bin/bitfield.js

$(BITFIELDD): package.json
	npm install

%.svg: %.json $(BITFIELDD)
	$(BITFIELD) -i $<  --vflip --hflip --lanes 2 --bits 12 > $@

.PHONY: clean
clean:
	-rm -r ./node_modules/

